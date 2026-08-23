#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CodeCaver
=========

Nástroj pro vložení takzvaného "code cave" do PE souboru (EXE / DLL).

Stručně řečeno: vezme existující spustitelný soubor a upraví ho tak, aby se při
jeho spuštění (nebo načtení) nejprve provedl krátký doplněný kus kódu, který
načte zadanou DLL knihovnu, a teprve poté se pokračuje v původním běhu
programu. Uživatel tak může "přidat" svůj kód do cizího programu bez nutnosti
znalosti jeho zdrojových kódů.

Autoři a úvod
-------------
Autor : Pavel Kalaš
Licence: MIT (viz soubor LICENSE)

UPOZORNĚNÍ K POUŽITÍ
--------------------
Tato technika je běžně používaná v malware analýze, reverzním inženýrství,
při tvorbě záplat a launcherů. Úpravou souboru:

  * vždy dojde k zneplatnění digitálního podpisu (Authenticode),
  * mění se obsah spustitelného souboru, což antiviry může označit za podezřelé.

Nástroj proto používejte POUZE na soubory, ke kterým máte oprávnění, a vždy
pracujte s kopií. Za jakékoli zneužití nese odpovědnost výhradně uživatel.

Princip fungování
-----------------
Celý postup se dá shrnout do pěti kroků, které se odehrají při zpracování:

  1. Přidá se nová sekce s názvem ".cave". Sekce má nastavené flagy tak, aby
     byla spustitelná, čitelná i zapisovatelná (RWX). Právě do ní se uloží jak
     nový kód, tak pomocná data (importy, název DLL, ...).

  2. Vytvoří se nová import tabulka. Ta obsahuje původní importy programu plus
     jeden nový import z knihovny kernel32.dll, konkrétně funkci LoadLibraryW.
     Díky tomu OS při startu sám vyřeší adresu LoadLibraryW a zapíše ji do
     našeho slotu v IAT (Import Address Table) - my se tak nemusíme obtěžovat
     ručním hledáním adresy funkce.

  3. Do nové sekce se zapíše:
        - shellcode (podporujeme 32bitové PE32/x86 i 64bitové PE32+/x64),
        - název naší DLL zakódovaný v UTF-16 (potřebný pro LoadLibraryW),
        - kompletní import struktury (INT, IAT, IMAGE_IMPORT_DESCRIPTOR,
          název "kernel32.dll" a název funkce "LoadLibraryW"),
        - jednobitový "guard" flag, který zajistí, že se DLL načte jen jednou
          (relevantní hlavně pro DLL, kde se DllMain volá víckrát).

  4. Ukazatel AddressOfEntryPoint se přepíše tak, aby ukazoval na začátek
     našeho shellcode. Loader tedy po startu spustí nejprve náš kód.

  5. Upravený soubor se uloží pod novým názvem (výchozí přípona "_caved").

Po spuštění pak proběhne zhruba toto:
  * OS načte program a skočí na náš shellcode (díky změněnému entry pointu),
  * shellcode zavolá LoadLibraryW(náš soubor DLL),
  * po návratu se obnoví registry a skočí se na původní entry point,
  * program běží dál naprosto normálně, jen s načtenou naší DLL.

Použití
-------
  python code_caver.py <cilovy_soubor> <nase_dll> [vystupni_soubor]

  Nebo bez argumentů - program se pak zeptá interaktivně.

Výstupní soubor se uloží vedle původního; výchozí název vznikne přidáním
přípony "_caved" před koncovku (např. "app.exe" -> "app_caved.exe").
"""

import os
import sys
import struct
import argparse

# ---------------------------------------------------------------------------
# Konfigurační konstanty PE formátu
# ---------------------------------------------------------------------------
# Tyto hodnoty se předávají do pole Characteristics jednotlivých sekcí.
# Dohromady znamenají: sekce obsahuje kód, je spustitelná, čitelná a zapisovatelná.
IMAGE_SCN_CNT_CODE = 0x00000020        # sekce obsahuje spustitelný kód
IMAGE_SCN_MEM_EXECUTE = 0x20000000     # sekce smí být spouštěna
IMAGE_SCN_MEM_READ = 0x40000000        # sekce smí být čtena
IMAGE_SCN_MEM_WRITE = 0x80000000       # sekce smí být zapisována

# Souhrnná kombinace flagů pro naši novou sekci (RWX).
NEW_SECTION_CHARS = (
    IMAGE_SCN_CNT_CODE
    | IMAGE_SCN_MEM_EXECUTE
    | IMAGE_SCN_MEM_READ
    | IMAGE_SCN_MEM_WRITE
)

# Název nové sekce. PE vyžaduje, aby položka Name měla přesně 8 bajtů,
# proto název doplníme nulami.
# (".cave" = tečka + 4 znaky + 3 nulové bajty = 8 bajtů)
CAVE_SECTION_NAME = b".cave" + b"\x00" * 3

# Název systémové knihovny a funkce, kterou importujeme. Jsou ukončené nulou,
# jak vyžaduje formát import tabulky.
KERNEL32_DLL_NAME = b"kernel32.dll\x00"
FUNCTION_NAME = b"LoadLibraryW\x00"


def align_up(value, alignment):
    """Zarovná `value` nahoru na násobek `alignment`.

    PE hlavičky vyžadují striktní zarovnání některých hodnot (např. RVA na
    SectionAlignment, velikost surových dat na FileAlignment). Tato pomocná
    funkce to řeší jednotně na jednom místě.
    """
    if alignment == 0:
        return value
    return (value + alignment - 1) // alignment * alignment


def i32(v):
    """Zabalí číslo jako signed 32bit little-endian.

    Používá se pro konstrukci shellcode, kde jsou relativní skoky ukládané
    právě jako 32bitová znaménková čísla (viz instrukce s rel32).
    """
    return struct.pack("<i", v)


# ---------------------------------------------------------------------------
# Konstrukce shellcode
# ---------------------------------------------------------------------------
# Shellcode je krátká sekvence strojových instrukcí, která se vloží na začátek
# provádění. Jeho úkol:
#   1. uchovat stav CPU (registry / stack),
#   2. zabránit opakovanému načtení DLL (guard flag),
#   3. zavolat LoadLibraryW s cestou k naší DLL,
#   4. obnovit stav a předat řízení původnímu entry pointu.
#
# Klíčová je volba RIP-relative / EIP-relative adresování, díky kterému kód
# funguje bez ohledu na to, na jakou adresu byl při startu namapován (ASLR).


def build_x64_shell(shell_rva, flag_rva, path_rva, iat_rva, orig_entry_rva):
    """Sestaví 64bitový (x64) shellcode.

    Parametry představují RVA (Relative Virtual Address) jednotlivých částí
    naší nové sekce. Z nich se dopočítají relativní offsety pro RIP-relative
    instrukce, takže výsledný kód je nezávislý na konkrétní bázové adrese.

    Logika kódu (pseudokód):
        uloz registry
        sub rsp, 0x28            ; shadow space + zarovnání stacku na 16 bajtů
        cmp  byte [flag], 0
        jne  skip                ; DLL už byla načtena -> pokračuj dál
        mov  byte [flag], 1
        lea  rcx, [path]
        call [iat]               ; LoadLibraryW(path)
    skip:
        add rsp, 0x28
        obnov registry
        jmp  orig_entry          ; předání řízení původnímu kódu
    """
    b = bytearray()

    # Zachováme 8 registrů. Sudý počet push instrukcí udrží stack správně
    # zarovnaný i pro pozdější volání (x64 ABI vyžaduje zarovnání na 16 bajtů).
    b += b"\x50"                 # push rax
    b += b"\x51"                 # push rcx
    b += b"\x52"                 # push rdx
    b += b"\x53"                 # push rbx
    b += b"\x41\x50"             # push r8
    b += b"\x41\x51"             # push r9
    b += b"\x41\x52"             # push r10
    b += b"\x41\x53"             # push r11
    b += b"\x48\x83\xEC\x28"     # sub rsp, 0x28 (shadow space + zarovnání)

    # cmp byte [rip+disp32], 0  - zkontroluj guard flag (délka instrukce = 7)
    # Disp32 se spočítá relativně k další instrukci.
    d = flag_rva - (shell_rva + len(b) + 7)
    b += b"\x80\x3D" + i32(d) + b"\x00"

    # jne skip (rel8). Cílovou adresu zatím neznáme, pozici si zapamatujeme
    # a doplníme ji zpětně, jakmile známe délku celého bloku.
    jne_pos = len(b)
    b += b"\x75\x00"             # jne (offset vyplníme později)

    # mov byte [rip+disp32], 1  - nastav guard flag na 1 (délka instrukce = 7)
    d = flag_rva - (shell_rva + len(b) + 7)
    b += b"\xC6\x05" + i32(d) + b"\x01"

    # lea rcx, [rip+disp32]     - načti adresu UTF-16 názvu DLL (délka = 7)
    # rcx je první argument volání (x64 calling convention).
    d = path_rva - (shell_rva + len(b) + 7)
    b += b"\x48\x8D\x0D" + i32(d)

    # call qword [rip+disp32]   - zavolej LoadLibraryW přes IAT (délka = 6)
    d = iat_rva - (shell_rva + len(b) + 6)
    b += b"\xFF\x15" + i32(d)

    # Zde začíná "skip" cíl. Spočítáme rel8 offset zpětně k JNE instrukci.
    skip = len(b)
    rel8 = skip - (jne_pos + 2)
    if not (-128 <= rel8 <= 127):
        raise ValueError("x64: jne rel8 mimo rozsah")
    b[jne_pos + 1] = rel8 & 0xFF

    # Obnovení stacku a registrů v opačném pořadí, než proběhl push.
    b += b"\x48\x83\xC4\x28"     # add rsp, 0x28
    b += b"\x41\x5B"             # pop r11
    b += b"\x41\x5A"             # pop r10
    b += b"\x41\x59"             # pop r9
    b += b"\x41\x58"             # pop r8
    b += b"\x5B"                 # pop rbx
    b += b"\x5A"                 # pop rdx
    b += b"\x59"                 # pop rcx
    b += b"\x58"                 # pop rax

    # jmp rel32 -> původní entry point (délka instrukce = 5)
    rel = orig_entry_rva - (shell_rva + len(b) + 5)
    b += b"\xE9" + i32(rel)
    return bytes(b)


def build_x86_shell(shell_rva, flag_rva, path_rva, iat_rva, orig_entry_rva):
    """Sestaví 32bitový (x86) shellcode.

    Oproti x64 je zde jiná calling convention (stdcall) a jiné adresování.
    Pro přístup k datům používáme trik "call next / pop ebp", čímž získáme
    aktuální adresu (EIP) do registru EBP a od ní počítáme offsety.

    Logika kódu (pseudokód):
        call next
    next:
        pop  ebp                 ; ebp = adresa 'next' (naše relativní báze)
        cmp  byte [ebp+flag], 0
        jne  skip
        mov  byte [ebp+flag], 1
        lea  eax, [ebp+path]
        push eax                 ; argument pro stdcall
        call [ebp+iat]           ; LoadLibraryW(path) - stdcall si uklidí arg
    skip:
        jmp  orig_entry
    """
    b = bytearray()

    # Získáme aktuální adresu do EBP (call pushne návratovou adresu = adresa
    # za call, kterou pak pop ebp přečte).
    b += b"\xE8\x00\x00\x00\x00" # call next
    b += b"\x5D"                 # pop ebp

    # cmp byte [ebp+disp32], 0  - guard flag (délka instrukce = 6)
    d = flag_rva - (shell_rva + 5)
    b += b"\x80\xBD" + i32(d) + b"\x00"

    jne_pos = len(b)
    b += b"\x75\x00"             # jne skip (rel8, doplníme zpětně)

    # mov byte [ebp+disp32], 1  - nastav guard flag (délka = 6)
    d = flag_rva - (shell_rva + 5)
    b += b"\xC6\x85" + i32(d) + b"\x01"

    # lea eax, [ebp+disp32]     - adresa UTF-16 názvu DLL (délka = 6)
    d = path_rva - (shell_rva + 5)
    b += b"\x8D\x85" + i32(d)

    b += b"\x50"                 # push eax (argument pro LoadLibraryW)

    # call dword [ebp+disp32]   - volání přes IAT (délka = 6)
    d = iat_rva - (shell_rva + 5)
    b += b"\xFF\x95" + i32(d)

    # Doplnění rel8 offsetu pro JNE.
    skip = len(b)
    rel8 = skip - (jne_pos + 2)
    if not (-128 <= rel8 <= 127):
        raise ValueError("x86: jne rel8 mimo rozsah")
    b[jne_pos + 1] = rel8 & 0xFF

    # jmp rel32 -> původní entry point (délka = 5)
    rel = orig_entry_rva - (shell_rva + len(b) + 5)
    b += b"\xE9" + i32(rel)
    return bytes(b)


def build_shellcode(bits, shell_rva, flag_rva, path_rva, iat_rva, orig_entry_rva):
    """Rozcestník - podle bitovosti PE vybere správný builder shellcode."""
    if bits == 64:
        return build_x64_shell(shell_rva, flag_rva, path_rva, iat_rva, orig_entry_rva)
    return build_x86_shell(shell_rva, flag_rva, path_rva, iat_rva, orig_entry_rva)


# ---------------------------------------------------------------------------
# PE parser / patcher
# ---------------------------------------------------------------------------
class Section:
    """Drží informace o jedné sekci PE souboru.

    __slots__ zrychluje přístup a šetří paměť - atributy jsou přesně dané.
    """
    __slots__ = ("name", "vsize", "va", "rawsize", "rawptr", "characteristics")


class PEFile:
    """Načte a rozparsuje PE soubor, poskytne přístup k hlavičkám a sekcím.

    Cílem je mít veškeré údaje, které potřebuje patcher, na jednom místě.
    Parser je záměrně úsporný - čteme jen to, co opravdu používáme.
    """

    def __init__(self, data):
        self.data = bytearray(data)      # upravitelná kopie celého souboru
        self.bits = 0                    # 32 nebo 64
        self.machine = 0                 # typ CPU (IMAGE_FILE_MACHINE_*)
        self.entry_rva = 0               # RVA původního entry pointu
        self.section_align = 0           # zarovnání sekcí v paměti
        self.file_align = 0              # zarovnání surových dat v souboru
        self.size_of_image = 0           # celková velikost obrazu v paměti
        self.size_of_headers = 0         # velikost všech hlaviček
        self.num_rva = 0                 # počet datových adresářů
        self.data_dir_off = 0            # offset na začátek data directories
        self.sections = []               # seznam sekcí (objekty Section)
        self._parse()

    def _parse(self):
        """Provede vlastní rozparsování hlaviček PE formátu."""
        # Ověření DOS hlavičky - každý PE začíná magickým "MZ".
        if len(self.data) < 0x40 or self.data[0:2] != b"MZ":
            raise ValueError("Soubor neni validni PE (chybi MZ/DOS hlavicka).")

        # e_lfanew (na offsetu 0x3C) ukazuje na začátek PE hlavičky.
        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("Soubor neni validni PE (chybi PE signatura).")

        pe = e_lfanew
        self.machine = struct.unpack_from("<H", self.data, pe + 4)[0]
        self.num_sections = struct.unpack_from("<H", self.data, pe + 6)[0]
        size_opt = struct.unpack_from("<H", self.data, pe + 20)[0]
        opt = pe + 24                  # začátek Optional headeru

        # Magické číslo rozliší PE32 (0x10B) od PE32+ (0x20B).
        magic = struct.unpack_from("<H", self.data, opt)[0]
        if magic == 0x20B:
            # 64bitový formát
            self.bits = 64
            self.image_base = struct.unpack_from("<Q", self.data, opt + 24)[0]
            self.num_rva = struct.unpack_from("<I", self.data, opt + 108)[0]
            self.data_dir_off = opt + 112
        elif magic == 0x10B:
            # 32bitový formát
            self.bits = 32
            self.image_base = struct.unpack_from("<I", self.data, opt + 28)[0]
            self.num_rva = struct.unpack_from("<I", self.data, opt + 92)[0]
            self.data_dir_off = opt + 96
        else:
            raise ValueError("Neznamy PE format (magic 0x%X)." % magic)

        # Načtení klíčových hodnot z Optional headeru.
        self.entry_rva = struct.unpack_from("<I", self.data, opt + 16)[0]
        self.section_align = struct.unpack_from("<I", self.data, opt + 32)[0]
        self.file_align = struct.unpack_from("<I", self.data, opt + 36)[0]
        self.size_of_image = struct.unpack_from("<I", self.data, opt + 56)[0]
        self.size_of_headers = struct.unpack_from("<I", self.data, opt + 60)[0]

        # Uložíme si offsety, které budeme později potřebovat pro zápis.
        self.opt_off = opt
        self.pe_off = pe
        self.sec_table_off = opt + size_opt   # začátek sekce section headers

        if self.section_align == 0 or self.file_align == 0:
            raise ValueError("PE ma nulove SectionAlignment/FileAlignment.")

        # Projdeme tabulku sekcí. Každý section header má 40 bajtů.
        self.sections = []
        for i in range(self.num_sections):
            off = self.sec_table_off + i * 40
            s = Section()
            s.name = bytes(self.data[off : off + 8])
            s.vsize = struct.unpack_from("<I", self.data, off + 8)[0]
            s.va = struct.unpack_from("<I", self.data, off + 12)[0]
            s.rawsize = struct.unpack_from("<I", self.data, off + 16)[0]
            s.rawptr = struct.unpack_from("<I", self.data, off + 20)[0]
            s.characteristics = struct.unpack_from("<I", self.data, off + 36)[0]
            self.sections.append(s)

    def rva_to_offset(self, rva):
        """Převede RVA na offset (pozici) v souboru.

        Prochází jednotlivé sekce a hledá, do které dané RVA spadá.
        """
        for s in self.sections:
            # Velikost sekce v paměti je max(vsize, rawsize) - tak ji mapuje loader.
            mapped = max(s.vsize, s.rawsize)
            if s.va <= rva < s.va + mapped:
                return s.rawptr + (rva - s.va)
        raise ValueError("RVA 0x%08X nelezi v zadne sekci." % rva)

    def data_dir(self, index, size=False):
        """Vrátí RVA (nebo velikost) z položky data directory na daném indexu.

        Každá položka má 8 bajtů: 4 bajty RVA + 4 bajty velikost.
        """
        off = self.data_dir_off + index * 8
        if size:
            return struct.unpack_from("<I", self.data, off + 4)[0]
        return struct.unpack_from("<I", self.data, off)[0]

    def set_data_dir(self, index, rva, sz):
        """Zapíše RVA a velikost do položky data directory na daném indexu."""
        off = self.data_dir_off + index * 8
        struct.pack_into("<II", self.data, off, rva, sz)

    def read_import_descriptors(self):
        """Vrátí seznam původních IMAGE_IMPORT_DESCRIPTOR (20 bajtů každý).

        Import tabulka je ukončená nulovým descriptorem, ten už nevracíme.
        """
        import_rva = self.data_dir(1)   # index 1 = import table
        if import_rva == 0:
            return []

        try:
            off = self.rva_to_offset(import_rva)
        except ValueError:
            return []

        descs = []
        for _ in range(1024):   # bezpečnostní strop proti poškozenému souboru
            if off + 20 > len(self.data):
                break
            d = bytes(self.data[off : off + 20])
            if d == b"\x00" * 20:       # nulový descriptor = konec tabulky
                break
            descs.append(d)
            off += 20
        return descs


def patch_pe(pe, dll_name):
    """Provede samotnou úpravu PE souboru (in-place přes pe.data).

    Argument `dll_name` je POUZE název souboru DLL (bez cesty). DLL se
    předpokládá ve složce cílového EXE/DLL, protože LoadLibraryW hledá
    standardně v adresáři aplikace.

    Vrací slovník s informacemi o provedeném patchi (pro výpis při ukončení).
    """

    # Velikost jednoho thunk záznamu: v x64 je 8 bajtů, v x86 4 bajty.
    thunk = 8 if pe.bits == 64 else 4

    # Délka shellcode nezávisí na konkrétních RVA, zjistíme ji jedním voláním
    # builderu s nulovými RVA.
    shell_len = len(build_shellcode(pe.bits, 0, 0, 0, 0, 0))

    original_descriptors = pe.read_import_descriptors()
    n_orig = len(original_descriptors)

    # ------------------------------------------------------------------
    # Krok 1: výpočet RVA nové sekce
    # ------------------------------------------------------------------
    # Nová sekce naváže hned za poslední existující sekci, zarovnaná na
    # SectionAlignment.
    last = pe.sections[-1]
    new_rva = align_up(last.va + max(last.vsize, last.rawsize), pe.section_align)

    # ------------------------------------------------------------------
    # Krok 2: rozvržení obsahu nové sekce
    # ------------------------------------------------------------------
    # Obsah sekce uspořádáme za sebe: shellcode, guard flag, název DLL,
    # název "kernel32.dll", import-by-name záznam, INT, IAT a descriptory.
    path_bytes = dll_name.encode("utf-16-le") + b"\x00\x00"

    off_shell = 0
    off_flag = shell_len
    off_path = align_up(off_flag + 1, 16)
    off_dllname = off_path + len(path_bytes)
    off_ibn = align_up(off_dllname + len(KERNEL32_DLL_NAME), 2)

    # IMAGE_IMPORT_BY_NAME = hint (2 bajty) + název funkce (ASCII + nula).
    ibn = struct.pack("<H", 0) + FUNCTION_NAME
    off_int = align_up(off_ibn + len(ibn), thunk)
    off_iat = off_int + thunk * 2
    off_desc = align_up(off_iat + thunk * 2, 16)

    n_desc = n_orig + 2   # původní descriptory + náš + terminátor
    total_size = off_desc + n_desc * 20

    # Společné RVA (bázová adresa sekce + relativní offset v sekci).
    shell_rva = new_rva + off_shell
    flag_rva = new_rva + off_flag
    path_rva = new_rva + off_path
    dllname_rva = new_rva + off_dllname
    ibn_rva = new_rva + off_ibn
    int_rva = new_rva + off_int
    iat_rva = new_rva + off_iat
    desc_rva = new_rva + off_desc

    # Nyní, když známe reálné RVA, sestavíme finální shellcode.
    shell = build_shellcode(
        pe.bits, shell_rva, flag_rva, path_rva, iat_rva, pe.entry_rva
    )

    # ------------------------------------------------------------------
    # Krok 3: sestavení obsahu sekce
    # ------------------------------------------------------------------
    content = bytearray(total_size)
    content[off_shell : off_shell + len(shell)] = shell
    content[off_flag] = 0                                    # guard flag = 0
    content[off_path : off_path + len(path_bytes)] = path_bytes
    content[off_dllname : off_dllname + len(KERNEL32_DLL_NAME)] = KERNEL32_DLL_NAME
    content[off_ibn : off_ibn + len(ibn)] = ibn

    fmt = "<Q" if thunk == 8 else "<I"
    # INT[0] ukazuje na náš IMAGE_IMPORT_BY_NAME; IAT[0] ukazuje na totéž,
    # ale loader ji při startu přepíše skutečnou adresou LoadLibraryW.
    struct.pack_into(fmt, content, off_int, ibn_rva)
    struct.pack_into(fmt, content, off_iat, ibn_rva)

    # Nakopírujeme původní import descriptory, pak přidáme náš vlastní.
    doff = off_desc
    for d in original_descriptors:
        content[doff : doff + 20] = d
        doff += 20

    # Náš descriptor: kernel32.dll -> LoadLibraryW.
    content[doff : doff + 20] = struct.pack(
        "<IIIII", int_rva, 0, 0, dllname_rva, iat_rva
    )

    # ------------------------------------------------------------------
    # Krok 4: zápis nové sekce a úprava hlaviček
    # ------------------------------------------------------------------
    # Ověříme, zda je v hlavičkách místo pro jeden další section header.
    needed = pe.sec_table_off + (pe.num_sections + 1) * 40
    if needed > pe.size_of_headers:
        raise ValueError(
            "Neni misto pro dalsi section header (SizeOfHeaders prilis male)."
        )

    new_vsize = total_size
    new_rawsize = align_up(total_size, pe.file_align)

    # Syrová data nové sekce se uloží na konec souboru, zarovnaná na FileAlignment.
    new_raw = align_up(len(pe.data), pe.file_align)
    if len(pe.data) < new_raw:
        pe.data += b"\x00" * (new_raw - len(pe.data))

    # Zápis nového section headeru (40 bajtů).
    secoff = pe.sec_table_off + pe.num_sections * 40
    header = struct.pack(
        "<8sIIIIIIHHI",
        CAVE_SECTION_NAME,   # Name
        new_vsize,           # VirtualSize
        new_rva,             # VirtualAddress
        new_rawsize,         # SizeOfRawData
        new_raw,             # PointerToRawData
        0, 0, 0, 0,          # relocations, linenumbers, jejich počty
        NEW_SECTION_CHARS,   # Characteristics
    )
    pe.data[secoff : secoff + 40] = header

    # Přilepíme syrová data sekce a doplníme nulami do zarovnané velikosti.
    pe.data += bytes(content)
    if len(content) < new_rawsize:
        pe.data += b"\x00" * (new_rawsize - len(content))

    # Aktualizace počtu sekcí v COFF hlavičce.
    struct.pack_into("<H", pe.data, pe.pe_off + 6, pe.num_sections + 1)

    # Aktualizace SizeOfImage - musí pokrýt i novou sekci.
    mem_size = align_up(new_vsize, pe.section_align)
    new_size_of_image = max(pe.size_of_image, new_rva + mem_size)
    struct.pack_into("<I", pe.data, pe.opt_off + 56, new_size_of_image)

    # AddressOfEntryPoint přesměrujeme na začátek našeho shellcode.
    struct.pack_into("<I", pe.data, pe.opt_off + 16, new_rva)

    # Nastavíme novou import tabulku (data directory index 1).
    pe.set_data_dir(1, desc_rva, n_desc * 20)

    # Zrušíme bound imports (index 11), aby loader nepoužil neplatné adresy,
    # které byly svázané se starou import tabulkou.
    if pe.num_rva > 11:
        pe.set_data_dir(11, 0, 0)

    return {
        "bits": pe.bits,
        "machine": pe.machine,
        "old_entry": pe.entry_rva,
        "new_entry": new_rva,
        "section_rva": new_rva,
        "section_vsize": new_vsize,
        "section_rawsize": new_rawsize,
        "section_rawptr": new_raw,
        "dll_path_rva": path_rva,
        "iat_rva": iat_rva,
        "import_desc_rva": desc_rva,
        "n_imports": n_desc,
    }


# ---------------------------------------------------------------------------
# Hlavní logika aplikace
# ---------------------------------------------------------------------------
def inject(target_path, dll_path, output_path):
    """Načte cílový soubor, provede patch a uloží výsledek.

    Toto je hlavní entry point celé logiky - spojuje parsování, patch a uložení.
    """
    if not os.path.isfile(target_path):
        raise FileNotFoundError("Cilovy soubor neexistuje: %s" % target_path)

    with open(target_path, "rb") as f:
        original = f.read()

    pe = PEFile(original)

    # Ukládáme jen název DLL (bez cesty) - LoadLibraryW ho nalezne v adresáři
    # cílového EXE/DLL.
    dll_name = os.path.basename(dll_path)
    info = patch_pe(pe, dll_name)

    with open(output_path, "wb") as f:
        f.write(bytes(pe.data))

    # Přehledný výpis výsledku pro uživatele.
    print("=" * 60)
    print("  CodeCaver - patch dokoncen")
    print("=" * 60)
    print("Cilovy soubor   : %s" % target_path)
    print("Architektura    : %s-bit (machine 0x%04X)" % (info["bits"], info["machine"]))
    print("Puvodni entry   : 0x%08X" % info["old_entry"])
    print("Novy entry      : 0x%08X (sekce .cave)" % info["new_entry"])
    print("Nova sekce      : .cave")
    print("  RVA           : 0x%08X" % info["section_rva"])
    print("  VirtualSize   : 0x%08X" % info["section_vsize"])
    print("  SizeOfRawData : 0x%08X" % info["section_rawsize"])
    print("  PointerToRaw  : 0x%08X" % info["section_rawptr"])
    print("Nazev DLL       : %s" % dll_name)
    print(
        "Import tabulka  : %d descriptoru (RVA 0x%08X)"
        % (info["n_imports"], info["import_desc_rva"])
    )
    print("IAT LoadLibraryW: 0x%08X" % info["iat_rva"])
    print("Vystupni soubor : %s" % output_path)
    print("=" * 60)
    print("POZOR: digitalni podpis souboru je nyni neplatny.")


def default_output_name(target_path):
    """Vytvoří výchozí název výstupu: <jmeno>_caved.<přípona>."""
    base, ext = os.path.splitext(target_path)
    return base + "_caved" + ext


def main(argv=None):
    """Zpracuje argumenty příkazové řádky a spustí inject().

    Podporuje jak plně neinteraktivní režim (tři argumenty), tak interaktivní
    režim, kdy se program na chybějící hodnoty sám zeptá.
    """
    parser = argparse.ArgumentParser(
        description="Do PE souboru (EXE/DLL) vlozi code cave, ktery zavola LoadLibraryW s cestou k DLL."
    )
    parser.add_argument("target", nargs="?", help="Cesta k cilovemu EXE/DLL souboru.")
    parser.add_argument("dll", nargs="?", help="Cesta k DLL, ktere se ma pri startu nacist.")
    parser.add_argument("output", nargs="?", help="Vystupni soubor (vychozi: <cil>_caved.<ext>).")
    args = parser.parse_args(argv)

    target = args.target
    dll = args.dll
    output = args.output

    # Interaktivní doplnění chybějících hodnot. strip('"') odstraní případné
    # uvozovky, které uživatel mohl omylem nakopírovat.
    if not target:
        target = input("Cesta k cilovemu EXE/DLL souboru: ").strip().strip('"')
    if not dll:
        dll = input("Cesta k DLL, ktere se ma injectnout: ").strip().strip('"')

    target = os.path.abspath(target)
    if not dll:
        raise SystemExit("Nebyla zadana cesta k DLL.")

    if not output:
        output = default_output_name(target)

    inject(target, dll, output)


if __name__ == "__main__":
    # Globální zachycení výjimek pro pěkné chybové hlášky namísto tracebacku.
    try:
        main()
    except KeyboardInterrupt:
        print("\nPreruseno.")
        sys.exit(130)
    except Exception as exc:
        print("CHYBA: %s" % exc, file=sys.stderr)
        sys.exit(1)
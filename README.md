# CodeCaver

Slušný kus nářadí pro každého, kdo se hrabe v PE souborech. CodeCaver vezme existující EXE nebo DLL, našije do něj novou spustitelnou sekci (takzvaný "code cave") a zařídí, aby se po spuštění programu nejdřív načetla vaše DLL knihovna, a teprve pak se program normálně rozjel. Bez znalosti zdrojáků, bez linkeru, jen čistá manipulace s binárkou.

Autor: **Pavel Kalaš** · Licence: **MIT**

---

## K čemu to vlastně je

Představte si, že chcete do nějakého programu přidat vlastní funkci, ale nemáte k dispozici zdrojový kód. CodeCaver vám to umožní jednoduchým trikem:

1. Přidá do souboru novou sekci `.cave` (s právy RWX, tedy spustitelnou, čitelnou i zapisovatelnou).
2. Vytvoří novou import tabulku, která kromě původních importů obsahuje i funkci `LoadLibraryW` z `kernel32.dll`.
3. Do nové sekce nacpe krátký shellcode, název vaší DLL a kompletní import strukturu.
4. Přepíše entry point tak, aby se při startu spustil nejdřív ten shellcode.
5. Shellcode zavolá `LoadLibraryW`, načte vaši DLL a pak skočí zpátky na původní vstupní bod.

Program pak běží normálně, jen má cestou načtenou i vaši knihovnu. Podporuje se **32-bit (x86)** i **64-bit (x64)**, takže to funguje prakticky na všem.

Typické využití: reverzní inženýrství, analýza vzorků, tvorba záplat, launchery, ale i věci kolem modů a úprav her.

---

## Installace

Žádná magie. Stačí Python 3.6+ a standardní knihovny, nic se neinstaluje.

```bash
git clone https://github.com/pavelkalas/CodeCaver.git
cd CodeCaver
```

Hotovo, můžete rovnou spouštět.

---

## Jak se to používá

### Základní použití

```bash
python code_caver.py cilovy_program.exe moje.dll
```

Tímhle se vytvoří kopie `cilovy_program_caved.exe` s načtením `moje.dll`.

### Vlastní výstupní soubor

```bash
python code_caver.py cilovy_program.exe moje.dll vystup_vyrobeny.exe
```

### Interaktivní režim

Když spustíte skript úplně bez argumentů, ptá se na jednotlivé hodnoty sám:

```bash
python code_caver.py
```

---

## Pár poznámek k použití

- **DLL dejte vedle cílového souboru.** Načítá se podle názvu, takže `moje.dll` musí ležet ve stejné složce jako upravené EXE/DLL.
- **Digitální podpis se tím zničí.** Úprava binárky vždycky zneplatní Authenticode. Není to bug, je to daň za to, co děláme.
- **Antiviry se budou cukat.** Jakákoliv úprava spustitelného souboru je pro ně podezřelá. Počítejte s tím.
- **Vždy pracujte s kopií.** Původní soubor se sice nemění (výstup má `_caved` v názvu), ale záloha nikdy neuškodí.
- **Používejte to jen na to, k čemu máte právo.** Cokoliv jiného si spořádejte s vlastním svědomím, autor za zneužití neručí.

---

## Jak to funguje technicky

Kdo se chce vrtat hloubš, tady je kostra celého postupu:

| Krok | Co se děje |
|------|------------|
| 1 | Zpracuje se PE hlavička a vytáhne se z ní vše potřebné (architektura, entry point, sekce, importy). |
| 2 | Vypočítá se RVA pro novou sekci `.cave` hned za poslední existující sekcí. |
| 3 | Sestaví se shellcode pro danou bitovost (x86 / x64). Používá relativní adresování, takže přežije i ASLR. |
| 4 | Vytvoří se nová import tabulka: původní descriptory + nový pro `kernel32.dll!LoadLibraryW`. |
| 5 | Vše se nacpe do nové sekce, opraví se SizeOfImage, počet sekcí a import data directory. |
| 6 | `AddressOfEntryPoint` se namíří na začátek shellcode. |

Shellcode pak dělá jen pár věcí: uchová registry, zkontroluje guard flag (ať se DLL nenačte dvakrát), zavolá `LoadLibraryW` a vrátí řízení původnímu kódu.

Celý kód je podrobně okomentovanej přímo ve zdrojáku, takže když vás zajímají detaily, mrkněte do `code_caver.py`.

---

## Soubory v projektu

```
CodeCaver/
├── code_caver.py   # jediný skript, co to celé dělá
├── README.md       # tenhle soubor
└── LICENSE         # MIT licence
```

---

## Licence

MIT. Podrobnosti najdete v souboru [LICENSE](LICENSE). Zkrátka: dělejte si s tím, co chcete, jen mě z toho nevoďte k soudu.
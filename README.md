# XNB Unpacker for Stardew Valley 1.6

A static web page (no server, no build step) that unpacks and repacks `.xnb` files in the browser.
It uses [xnb.js](https://github.com/lybell-art/xnb-js) and adds the Stardew Valley **1.6.15** data
layouts, generated from the game's own `StardewValley.GameData.dll`.

## Run it
ES modules need http(s), so double-clicking `index.html` will not work. Either:
- push these files to a GitHub repo and enable **Pages**, or
- run `python -m http.server` in this folder and open http://localhost:8000

## Files
- `index.html` – the page (drag & drop, YAML / content-only options, zip download)
- `schemes-1.6.js` – 139 data types + 28 enums for xnb.js (`addSchemes` / `addEnums`)
- `zip.js` – small dependency-free zip writer for "Download all"
- `tools/gen_schemes.py` – regenerates `schemes-1.6.js` from a new `StardewValley.GameData.dll`
- `tools/verify_xnb.py` – decodes real `.xnb` files with the generated schemes and tells you if any byte is left over

## After a game update
```
python tools/gen_schemes.py "<game folder>/StardewValley.GameData.dll" .
python tools/verify_xnb.py schemes-1.6.json Buildings.xnb Shops.xnb Machines.xnb
```
Python 3.8+, no packages needed.

## Known limits
- `Data/Powers` has a `Dictionary<string, object>` field. xnb.js has no reader for `object`, so that one file may fail.
- Classes with both properties and fields (Shops, Machines, FruitTrees, FishPonds, WorldMap, Tailoring) assume
  xnb.js/XNA order "properties first". Run `verify_xnb.py` on those files to confirm.
- xnb.js cannot write LZX, so repacked files are uncompressed or LZ4 (the game reads both).

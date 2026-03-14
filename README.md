This web utility scans a folder of password list files for a given password.

You can enter raw or encoded passwords – the script will automatically try to
decode common encodings (hex, Base64, URL‑percent, ROT13, ASCII codes) before
searching the lists.

The tool can also check a handful of popular password lists hosted online (for
example the SecLists project on GitHub).  After a local scan fails you will be
prompted to include the defaults or supply your own URLs – the lists are fetched
on the fly and scanned line‑by‑line.

To run: python app.py

Then open http://localhost:5000 in your browser.

**Important**: DONT USE THIS FOR CRIMINAL PURPOSES.
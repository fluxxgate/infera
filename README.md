# inferas

inferas is a small runtime helper to:
- install Python packages for an application
- run a module via `python -m <module>`
- maintain a small JSON metadata file (version + build)

Install (editable) and use:
$ python -m pip install -e .
$ inferas --install requests numpy --run my_app.main


# note

Everything was developed on a chromebook this module was not tested once so be cautious.
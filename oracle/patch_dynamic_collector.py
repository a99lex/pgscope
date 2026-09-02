from pathlib import Path


path = Path("/app/oracle_collector.py")
source = path.read_text()

function_marker = "\ndef insert_snapshot(\n"
helper = '''
\ndef clean_nul(value):
    """Remove Oracle NUL characters before writing text to PostgreSQL."""
    if isinstance(value, str):
        return value.replace("\\x00", "")
    if isinstance(value, list):
        return [clean_nul(item) for item in value]
    if isinstance(value, dict):
        return {key: clean_nul(item) for key, item in value.items()}
    return value
'''

if "def clean_nul(value):" not in source:
    if function_marker not in source:
        raise RuntimeError("insert_snapshot marker was not found")
    source = source.replace(function_marker, helper + function_marker, 1)

body_marker = "):\n    dbname = (\n"
if "payload = clean_nul(payload)" not in source:
    if body_marker not in source:
        raise RuntimeError("insert_snapshot body marker was not found")
    source = source.replace(
        body_marker,
        "):\n    payload = clean_nul(payload)\n\n    dbname = (\n",
        1,
    )

path.write_text(source)

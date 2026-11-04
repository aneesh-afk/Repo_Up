def helper():
    # Intentional: Exception handling issue (bare except or pass)
    try:
        open("nonexistent.txt")
    except:
        pass

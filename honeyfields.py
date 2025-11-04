def check_honeyfields(form_data):
    """Return (triggered, field_name, value) if any '__do_not_fill' field is filled."""
    for k, v in form_data.items():
        if "__do_not_fill" in k and v and str(v).strip():
            return True, k, v
    return False, None, None
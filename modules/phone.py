def analyze_phone(phone):
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, timezone

        parsed = phonenumbers.parse(phone, None)
        valid = phonenumbers.is_valid_number(parsed)
        possible = phonenumbers.is_possible_number(parsed)

        return {
            "type": "phone",
            "target": phone,
            "summary": "Public phone-number metadata",
            "findings": [
                {"label": "Validity", "value": "Valid" if valid else "Not valid", "status": "good" if valid else "bad"},
                {"label": "Possible", "value": "Yes" if possible else "No", "status": "good" if possible else "warn"},
                {"label": "Region", "value": geocoder.description_for_number(parsed, "en") or "Unavailable", "status": "info"},
                {"label": "Carrier", "value": carrier.name_for_number(parsed, "en") or "Unavailable", "status": "info"},
                {"label": "Time zone", "value": ", ".join(timezone.time_zones_for_number(parsed)) or "Unavailable", "status": "info"},
            ],
            "notice": "Region/carrier metadata is not an exact address or proof of subscriber identity."
        }
    except Exception as exc:
        return {
            "type": "phone",
            "target": phone,
            "summary": "Phone parsing",
            "findings": [{"label": "Status", "value": f"Could not parse: {exc}", "status": "warn"}],
            "notice": "Use an international format such as +1..., +91..., etc."
        }

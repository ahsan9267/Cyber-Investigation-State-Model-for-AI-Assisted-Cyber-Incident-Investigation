"""Map Windows System Event 7045 service-installation fields."""


def map_service_installation(fields: dict, warnings: list) -> dict:
    def text(key):
        value = fields.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            warnings.append(f"Invalid service text field: {key}")
            return None
        return value if value.strip() else None

    return {
        "name": text("serviceName"),
        # Preserve the full value: it may include executable arguments.
        "image_path_original": text("imagePath"),
        "service_type": text("serviceType"),
        "start_type": text("startType"),
        "account": text("accountName"),
    }
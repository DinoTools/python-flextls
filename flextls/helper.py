from flextls import registry


def get_version_name(protocol_version):
    if protocol_version == registry.version.SSLv2:
        return "SSLv2"
    if protocol_version == registry.version.SSLv3:
        return "SSLv3"
    if protocol_version == registry.version.TLSv10:
        return "TLSv1.0"
    if protocol_version == registry.version.TLSv11:
        return "TLSv1.1"
    if protocol_version == registry.version.TLSv12:
        return "TLSv1.2"

    return 'unknown'

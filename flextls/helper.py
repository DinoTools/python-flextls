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
    if protocol_version == registry.version.DTLSv10:
        return "DTLSv10"

    return 'unknown'


def get_version(protocol_version):
    if protocol_version == registry.version.SSLv3:
        return (3, 0)
    elif protocol_version == registry.version.TLSv10:
        return (3, 1)
    elif protocol_version == registry.version.TLSv11:
        return (3, 2)
    elif protocol_version == registry.version.TLSv12:
        return (3, 3)
    elif protocol_version == registry.version.DTLSv10:
        return (0xfe, 0xff)

    # ToDo: raise exception?


def get_tls_version(protocol_version):
    return get_version(protocol_version)
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


def get_tls_version(protocol_version):
    ver_major = 3
    if protocol_version == registry.version.SSLv3:
        ver_minor = 0
    elif protocol_version == registry.version.TLSv10:
        ver_minor = 1
    elif protocol_version == registry.version.TLSv11:
        ver_minor = 2
    elif protocol_version == registry.version.TLSv12:
        ver_minor = 3

    return ver_major, ver_minor

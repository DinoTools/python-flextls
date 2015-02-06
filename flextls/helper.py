from flextls import registry


def get_version_name(protocol_version):
    ver = registry.version_info.get(protocol_version)
    if ver:
        return ver.name

    return 'unknown'


def get_version_id(protocol_version):
    ver = registry.version_info.get(protocol_version)
    if ver:
        return ver.version_id

    # ToDo: raise exception?


def get_tls_version(protocol_version):
    return get_version_id(protocol_version)
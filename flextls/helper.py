from flextls import registry


def get_version_by_version_id(version_id):
    """
    Get the internal version ID be the version.

    :param Tuple version_id: Major and minor version number
    :return: Internal version ID
    :rtype: Integer|None
    """
    for ver in registry.version_info:
        if ver.version_id == version_id:
            return ver.id

    return None


def get_version_name(version_id):
    """
    Get the name of a protocol version by the internal version ID.

    :param Integer version_id: Internal protocol version ID
    :return: Name of the version
    :rtype: String
    """
    ver = registry.version_info.get(version_id)
    if ver:
        return ver.name

    return 'unknown'


def get_version_id(protocol_version):
    """
    Get a tuple with major and minor version number

    :param Integer protocol_version: Internal version ID
    :return: Tuple of major and minor protocol version
    :rtype: Tuple
    """
    ver = registry.version_info.get(protocol_version)
    if ver:
        return ver.version_id

    # ToDo: raise exception?


def get_tls_version(protocol_version):
    return get_version_id(protocol_version)
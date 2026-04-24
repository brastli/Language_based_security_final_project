from lxml import etree
def parse_xml(xml_string):
    # 漏洞：未禁用外部实体解析
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(xml_string, parser)
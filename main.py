import sys
from Base.base import Registers
from Base.certificate_proc import cert_proc
from Base.load_lints import *
from Base.do_lints import do_lints
from Base.show_lints import *
from optparse import OptionParser
from Utils.utils import str_to_list


if __name__ == '__main__':

    # Init var
    custom_lints = None
    exclude_names = None
    exclude_sources = None

    # Init args
    parser = OptionParser()
    parser.add_option("--listLintsJson", dest="list_lints_json", default=False,
                      help="Print lints in JSON format, one per line")
    parser.add_option("--listLintsSource", dest="list_lints_source", default=False,
                      help="Print list of lint sources, one per line")
    parser.add_option("--customLints", dest="custom_lints",
                      help="Comma-separated list of custom lints to registry")
    parser.add_option("--excludeNames", dest="exclude_names",
                      help="Comma-separated list of lints to exclude by name")
    parser.add_option("--excludeSources", dest="exclude_sources",
                      help="Comma-separated list of lint sources to exclude")
    parser.add_option("--format", dest="format", default="der",
                      help="Default der, one of (pem, der, base64)")
    parser.add_option("-f", "--file", dest="cert_file",
                      help="Cert to be check with lints")
    (options, args) = parser.parse_args()

    # Check input args
    if options.custom_lints:
        custom_lints = str_to_list(options.custom_lints)
    if options.exclude_names:
        exclude_names = str_to_list(options.exclude_names)
    if options.exclude_sources:
        exclude_sources = str_to_list(options.exclude_sources)

    # Import all register Lints, Exclude Lints by Source
    import_all_lints_for_register(custom_lints, exclude_sources)

    # Exclude Lints by name
    exclude_lints(Registers, exclude_names)

    # Check list-lints args
    if options.list_lints_json:
        show_lints_json(Registers)
        sys.exit(0)

    if options.list_lints_source:
        show_lints_source(Registers)
        sys.exit(0)

    # Analyze cert to asn1 struct
    cert = cert_proc(options.format, options.cert_file)

    # Do lints check
    do_lints(Registers, cert)

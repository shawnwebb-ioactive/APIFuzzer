# /// script
# dependencies = [
#   "boto3==1.35.42",
#   "botocore==1.35.42",
#   "certifi==2024.8.30",
#   "charset-normalizer==3.4.0",
#   "click==8.1.7",
#   "decorator==5.1.1",
#   "idna==3.10",
#   "jmespath==1.0.1",
#   "json-ref-dict==0.7.2",
#   "jsonpath-ng==1.5.2",
#   "jsonpointer==2.4",
#   "junit-xml==1.9",
#   "kittyfuzzer==0.7.4",
#   "mypy-extensions==1.0.0",
#   "packaging==24.1",
#   "pathspec==0.12.1",
#   "platformdirs==4.3.6",
#   "ply==3.11",
#   "pycurl==7.45.2",
#   "python-dateutil==2.9.0.post0",
#   "PyYAML==6.0.1",
#   "requests==2.32.3",
#   "requests-auth-aws-sigv4==0.7",
#   "ruamel.yaml==0.16.12",
#   "s3transfer==0.10.3",
#   "six==1.16.0",
#   "setuptools",
#   "tomli==2.0.2",
#   "typing_extensions==4.12.2",
#   "urllib3==2.2.3"
#  ]
# ///

import argparse
import signal
import sys
import tempfile
import traceback
from logging import _nameToLevel as levelNames

from apifuzzer.fuzz_utils import FailedToParseFileException
from apifuzzer.fuzzer import Fuzzer
from apifuzzer.utils import json_data, str2bool
from apifuzzer.version import get_version

if __name__ == "__main__":

    def signal_handler(sig, frame):
        sys.exit(0)

    parser = argparse.ArgumentParser(description="APIFuzzer configuration")
    parser.add_argument(
        "-s",
        "--src_file",
        type=str,
        required=False,
        help="API definition file path. JSON and YAML format is supported",
        dest="src_file",
    )
    parser.add_argument(
        "--src_url",
        type=str,
        required=False,
        help="API definition url. JSON and YAML format is supported",
        dest="src_url",
    )
    parser.add_argument(
        "-r",
        "--report_dir",
        type=str,
        required=False,
        help="Directory where error reports will be saved. Default is temporally generated directory",
        dest="report_dir",
        default=tempfile.mkdtemp(),
    )
    parser.add_argument(
        "--level",
        type=int,
        required=False,
        help="Test deepness: [1,2], higher is the deeper !!!Not implemented!!!",
        dest="level",
        default=1,
    )
    parser.add_argument(
        "-u",
        "--url",
        type=str,
        required=False,
        help="Use CLI defined url instead compile the url from the API definition. Useful for testing",
        dest="alternate_url",
        default=None,
    )
    parser.add_argument(
        "-t",
        "--test_report",
        type=str,
        required=False,
        help="JUnit test result xml save path ",
        dest="test_result_dst",
        default=None,
    )
    parser.add_argument(
        "--log",
        type=str,
        required=False,
        help="Use different log level than the default WARNING",
        dest="log_level",
        default="warning",
        choices=[level.lower() for level in levelNames if isinstance(level, str)],
    )
    parser.add_argument(
        "--basic_output",
        type=str2bool,
        required=False,
        help="Use basic output for logging (useful if running in jenkins). Example --basic_output=True",
        dest="basic_output",
        default=False,
    )
    parser.add_argument(
        "--headers",
        type=json_data,
        required=False,
        help='Http request headers added to all request. Example: \'[{"Authorization": "SuperSecret"}, '
        '{"Auth2": "asd"}]\'',
        dest="headers",
        default=None,
    )
    parser.add_argument(
        "--aws_auth",
        action=argparse.BooleanOptionalAction,
        required=False,
        help="Use AWS SigV4 authentication",
        dest="aws_auth",
    )
    parser.add_argument(
        "--aws_profile",
        required=False,
        help="AWS profile to use",
        dest="aws_profile",
        default=None,
    )
    parser.add_argument(
        "--aws_region_name",
        help="AWS region",
        dest="aws_region",
        default=None,
    )
    parser.add_argument("-v", "--version", action="version", version=get_version())
    args = parser.parse_args()
    if args.src_file is None and args.src_url is None:
        argparse.ArgumentTypeError(
            "No API definition source provided -s, --src_file or --src_url should be defined"
        )
        exit()
    prog = Fuzzer(
        report_dir=args.report_dir,
        test_level=args.level,
        alternate_url=args.alternate_url,
        test_result_dst=args.test_result_dst,
        log_level=args.log_level,
        basic_output=args.basic_output,
        auth_headers=args.headers,
        api_definition_url=args.src_url,
        api_definition_file=args.src_file,
        junit_report_path=args.test_result_dst,
        aws_auth=args.aws_auth,
        aws_profile=args.aws_profile,
        aws_region=args.aws_region,
    )
    try:
        prog.prepare()
    except FailedToParseFileException:
        print("Failed to parse API definition")
        exit(1)
    except Exception as e:
        print(
            f"Unexpected exception happened during fuzz test preparation: {traceback.print_stack(*sys.exc_info())}.\n"
            f" Feel free to report the issue",
        )
        exit(1)
    signal.signal(signal.SIGINT, signal_handler)
    prog.run()

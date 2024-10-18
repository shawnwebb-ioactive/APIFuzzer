import json
import os
from time import time, perf_counter

from bitstring import Bits
from junit_xml import TestSuite, TestCase, to_xml_report_file
from kitty.targets.server import ServerTarget

from apifuzzer.apifuzzerreport import ApifuzzerReport as Report
from apifuzzer.fuzzer_target.request_base_functions import FuzzerTargetBase
from apifuzzer.utils import try_b64encode, get_logger


class Return:
    pass


class FuzzerTarget(FuzzerTargetBase, ServerTarget):
    def not_implemented(self, func_name):
        _ = func_name
        pass

    def __init__(self, name, base_url, report_dir, auth_headers, junit_report_path, aws_auth=False):
        super(ServerTarget, self).__init__(name)  # pylint: disable=E1003
        super(FuzzerTargetBase, self).__init__(auth_headers)  # pylint: disable=E1003
        self.logger = get_logger(self.__class__.__name__)
        self.base_url = base_url
        self.accepted_status_codes = list(range(200, 300)) + list(range(400, 500))
        self.auth_headers = auth_headers
        self.report_dir = report_dir
        self.junit_report_path = junit_report_path
        self.failed_test = list()
        self.logger.info("Logger initialized")
        self.resp_headers = dict()
        self.transmit_start_test = None
        self.aws_auth = aws_auth

    def pre_test(self, test_num):
        """
        Called when a test is started
        """
        self.test_number = test_num
        self.report = Report(self.name or str(test_num))
        if self.controller:
            self.controller.pre_test(test_number=self.test_number)
        for monitor in self.monitors:
            monitor.pre_test(test_number=self.test_number)
        self.report.add("test_number", test_num)
        self.report.add("state", "STARTED")
        self.transmit_start_test = perf_counter()

    def transmit(self, **kwargs):
        """
        Prepares fuzz HTTP request, sends and processes the response
        :param kwargs: url, method, params, querystring, etc
        :return:
        """
        self.logger.debug("Transmit: {}".format(kwargs))
        try:
            _req_url = list()
            for url_part in self.base_url, kwargs["url"]:
                if not url_part:
                    continue
                elif isinstance(url_part, Bits):
                    url_part = url_part.tobytes()
                elif isinstance(url_part, bytes):
                    url_part = url_part.decode()
                _req_url.append(url_part.strip("/"))
            kwargs.pop("url")
            # Replace back the placeholder for '/'
            # (this happens in expand_path_variables,
            # but if we don't have any path_variables, it won't)
            request_url = "/".join(_req_url).replace("+", "/")
            query_params = None

            if kwargs.get("params") is not None:
                self.logger.debug(
                    ("Adding query params: {}".format(kwargs.get("params", {})))
                )
                query_params = self.format_pycurl_query_param(
                    request_url, kwargs.get("params", {})
                )
                kwargs.pop("params")
            if kwargs.get("path_variables") is not None:
                request_url = self.expand_path_variables(
                    request_url, kwargs.get("path_variables")
                )
                kwargs.pop("path_variables")
            if kwargs.get("data") is not None:
                kwargs["data"] = self.fix_data(kwargs.get("data"))
            if query_params is not None:
                request_url = "{}{}".format(request_url, query_params)
            method = kwargs["method"]
            content_type = kwargs.get("content_type")
            kwargs.pop("content_type", None)
            self.logger.info("Request URL : {} {}".format(method, request_url))
            if kwargs.get("data") is not None:
                self.logger.info(
                    "Request data:{}".format(json.dumps(dict(kwargs.get("data"))))
                )
            if isinstance(method, Bits):
                method = method.tobytes()
            if isinstance(method, bytes):
                method = method.decode()
            kwargs.pop("method")
            kwargs["headers"] = self.compile_headers(kwargs.get("headers"))
            self.logger.debug(
                "Request url:{}\nRequest method: {}\nRequest headers: {}\nRequest body: {}".format(
                    request_url,
                    method,
                    json.dumps(dict(kwargs.get("headers", {})), indent=2),
                    kwargs.get("data"),
                )
            )
            self.report.set_status(Report.PASSED)
            self.report.add("request_url", request_url)
            self.report.add("request_method", method)
            self.report.add(
                "request_headers", json.dumps(dict(kwargs.get("headers", {})))
            )
            try:
                import requests
                from requests_auth_aws_sigv4 import AWSSigV4
                import boto3

                session = boto3.Session()

                arguments = dict(
                    method=method,
                    url=request_url,
                    params=kwargs.get("params", {}),
                    data=kwargs.get("data", {}),
                    headers=kwargs.get("headers"),
                )

                if self.aws_auth:
                    arguments["auth"] = AWSSigV4("execute-api", session=session)

                req = requests.request(**arguments)
                _return = Return()
                _return.status_code = req.status_code
                _return.headers = req.headers
                _return.content = req.content
                _return.request = Return()
                _return.request.headers = req.request.headers
                _return.request.body = req.request.body
            except Exception as e:
                self.logger.exception(e)
                self.report.set_status(Report.ERROR)
                self.logger.error("Request failed, reason: {}".format(e))
                self.report.add(
                    "request_sending_failed", e.msg if hasattr(e, "msg") else str(e)
                )
                # self.report.add('request_sending_failed', e.msg if hasattr(e, 'msg') else e)
                self.report.add("request_method", method)
                return
            # overwrite request headers in report, add auto generated ones
            self.report.add(
                "request_headers",
                try_b64encode(json.dumps(dict(_return.request.headers))),
            )
            self.logger.debug(
                "Response code:{}\nResponse headers: {}\nResponse body: {}".format(
                    _return.status_code,
                    json.dumps(dict(_return.headers), indent=2),
                    _return.content,
                )
            )
            self.report.add("request_body", _return.request.body)
            self.report.add("response", _return.content.decode())
            status_code = _return.status_code
            if not status_code:
                self.logger.warning(f"Failed to parse http response code, continue...")
                self.report.set_status(Report.ERROR)
                self.report.add("details", "Failed to parse http response code")
            elif status_code not in self.accepted_status_codes:
                if self.report.get_status() != Report.ERROR:
                    self.report.set_status(Report.FAILED)
                self.report.add("parsed_status_code", status_code)
                self.report_add_basic_msg(
                    ("Return code %s is not in the expected list:", status_code)
                )
            return _return
        except (
            UnicodeDecodeError,
            UnicodeEncodeError,
        ) as e:  # request failure such as InvalidHeader
            self.report_add_basic_msg(
                ("Failed to parse http response code, exception occurred: %s", e)
            )

    def post_test(self, test_num):
        """Called after a test is completed, perform cleanup etc."""
        if self.report.get("report") is None:
            self.report.add("reason", self.report.get_status())
        super(ServerTarget, self).post_test(test_num)  # pylint: disable=E1003
        if self.junit_report_path:
            report_dict = self.report.to_dict()
            test_case = TestCase(
                name=f"{self.test_number}: {report_dict['request_url']}",
                status=self.report.get_status(),
                timestamp=time(),
                elapsed_sec=perf_counter() - self.transmit_start_test,
            )
            if self.report.get_status() == Report.FAILED:
                test_case.add_failure_info(message=json.dumps(self.report.to_dict()))
            if self.report.get_status() == Report.ERROR:
                test_case.add_error_info(message=json.dumps(self.report.to_dict()))
            self.failed_test.append(test_case)
            self.save_report_to_disc()

    def save_report_to_disc(self):
        self.logger.info("Report: {}".format(self.report.to_dict()))
        try:
            if not os.path.exists(os.path.dirname(self.report_dir)):
                try:
                    os.makedirs(os.path.dirname(self.report_dir))
                except OSError:
                    pass
            with open(
                f"{self.report_dir}/{str(self.test_number + 1).zfill(4)}_{int(time())}.json",
                "w",
            ) as report_dump_file:
                report_dump_file.write(json.dumps(self.report.to_dict()))
        except Exception as e:
            self.logger.error(
                f'Failed to save report "{self.report.to_dict()}" to {self.report_dir} because: {e}'
            )

    def report_add_basic_msg(self, msg):
        self.report.set_status(Report.FAILED)
        self.logger.warning(msg)
        self.report.failed(msg)

    def teardown(self):
        if len(self.failed_test):
            test_cases = self.failed_test
        else:
            test_cases = list()
            test_cases.append(TestCase(name="Fuzz test succeed", status="Pass"))
        if self.junit_report_path:
            with open(self.junit_report_path, "w") as report_file:
                to_xml_report_file(
                    report_file,
                    [
                        TestSuite(
                            name="API Fuzzer", test_cases=test_cases, timestamp=time()
                        )
                    ],
                    prettyprint=True,
                )
        super(ServerTarget, self).teardown()  # pylint: disable=E1003

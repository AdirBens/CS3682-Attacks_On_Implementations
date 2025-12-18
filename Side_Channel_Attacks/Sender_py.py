from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass
from io import BytesIO
import threading
from typing import Dict, Any, Tuple, List, Optional
import pycurl
import urllib
from timing_attack import robust_median
import logging

#### LOGGER ####
logging.basicConfig(level=logging.INFO)


@dataclass
class TimingResult:
    def __init__(self, body: str, time_us: int, correct: bool, raw_server_ns: int):
        self.body = body
        self.time_us = time_us
        self.correct = correct
        self.raw_server_ns = raw_server_ns
    
    def failed(self):
        return TimingResult(body="", time_us=0, correct=False, raw_server_ns=0)

    def __repr__(self):
        return f"TimingResult(time={self.time_us}µs, correct={self.correct})"



class RequestSender(ABC):
    @abstractmethod
    def send(self, payload: Dict[str, Any]) -> Tuple[str, int]: ...
    
    @abstractmethod
    def close_sessions(self) -> None: ...

class PycurlHTTPSender(RequestSender):
    def __init__(
        self,
        url: str,
        base_payload: Dict[str, Any],
        timeout_sec: float = 5.0,
        max_workers: int = 100,
        warmup_requests: int = 3,
        baseline_samples: int = 10
    ):
        self.url = url.rstrip("/") + "/"
        self.fixed_payload = base_payload.copy()
        self.timeout_sec = timeout_sec
        self.max_workers = max_workers
        self.warmup_requests = warmup_requests
        self.baseline_samples = baseline_samples

        self._thread_local = threading.local()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

        self._baseline_ns = 0
        self._is_initialized = False

    @contextmanager
    def _managed_curl(self):
        instance = self._get_curl_instance()
        
        with self._curl_lock:
            if instance not in self._curl_instances:
                self._curl_instances.append(instance)

        try:
            yield instance
        finally:
            instance.reset()

    def _get_curl_instance(self):
        if not hasattr(self._thread_local, 'curl'):
            # TODO: change consts to variables
            c = pycurl.Curl()
            c.setopt(pycurl.FORBID_REUSE, 0)
            c.setopt(pycurl.TCP_KEEPALIVE, 1)
            c.setopt(pycurl.TIMEOUT, 6)
            c.setopt(pycurl.CONNECTTIMEOUT, 5)
            c.setopt(pycurl.HTTPHEADER, ["Connection: keep-alive"])
            c.setopt(pycurl.MAXREDIRS, 5)
            try:
                c.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_2TLS)
            except AttributeError:
                pass
            self._thread_local.curl = c
            
        return self._thread_local.curl
    
    def _do_warmup(self):
        warmup_futures = []
        for i in range(self.warmup_requests):
            payload = {"password": f"warm{i:04d}"}
            warmup_futures.append(
                self.executor.submit(self._single_request_raw, payload)
            )
        
        for future in warmup_futures:
            try:
                future.result()
            except Exception as e:
                # TODO: log the exception
                pass

    def _estimate_baseline(self):
        baseline_times: List[int] = []
        failed_count = 0

        for _ in range(self.baseline_samples):
            result = self._single_request_raw({"password": "@wrongwrongwrong@"})
            if result.raw_server_ns > 0:
                baseline_times.append(result.raw_server_ns)
            else:
                failed_count += 1
        
        self._baseline_ns = robust_median(samples=baseline_times) if baseline_times else 0

    def _single_request_raw(self, variable_payload: Dict[str, Any]) -> TimingResult:
        payload = self.fixed_payload | variable_payload
        url = f"{self.url}?{urllib.parse.urlencode(payload)}"
        buffer = BytesIO()

        with self._managed_curl() as curl:
            try:
                curl.setopt(pycurl.URL, url)
                curl.setopt(pycurl.WRITEFUNCTION, buffer.write)
                curl.perform()
                
                return self._process_response(curl, buffer)
                
            except pycurl.error:
                return TimingResult.failed()

    def _process_response(self, curl, buffer) -> TimingResult:
        pre = curl.getinfo(pycurl.PRETRANSFER_TIME)
        start = curl.getinfo(pycurl.STARTTRANSFER_TIME)
        status = curl.getinfo(pycurl.RESPONSE_CODE)
        
        body = buffer.getvalue().strip().decode('utf-8', errors='ignore')
        server_ns = int((start - pre) * 1_000_000_000)

        with self._baseline_lock:
            corrected_ns = max(0, server_ns - self._baseline_ns)

        return TimingResult(
            body=body,
            time_us=corrected_ns // 1000,
            correct=(status == 200 and body == "1"),
            raw_server_ns=server_ns
        )
    
    def _init(self):
        if not self._is_initialized:
            self._do_warmup()
            self._estimate_baseline()
            self._is_initialized = True

    def send(self, payload: Dict[str, Any]) -> TimingResult:
        if not self._is_initialized:
            self._init()
        
        return self._single_request_raw(payload)
    
    def send_many(self, payloads: List[Dict[str, Any]]) -> List[TimingResult]:
        futures = [self.executor.submit(self._single_request_raw, p) for p in payloads]
        results = []

        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                results.append(TimingResult.failed())

        return results

    def close_sessions(self) -> None:
        """Properly shuts down the executor and closes all pycurl instances."""
        self.executor.shutdown(wait=True)
        with self._curl_lock:
            for instance in self._curl_instances:
                try:
                    instance.close()
                except Exception:
                    pass

            self._curl_instances.clear()

    



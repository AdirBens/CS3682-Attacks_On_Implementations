from dataclasses import dataclass
import urllib.parse
import time
import pycurl
from io import BytesIO
from typing import Dict, Any, Tuple, List, Optional
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import statistics

_thread_local = threading.local()





class RequestSender(ABC):
    @abstractmethod
    def send(self, payload: Dict[str, Any]) -> Tuple[str, int]: ...
    
    @abstractmethod
    def close_sessions(self) -> None: ...


@dataclass
class TimingResult:
    def __init__(self, body: str, time_us: int, correct: bool, raw_server_ns: int):
        self.body = body
        self.time_us = time_us
        self.correct = correct
        self.raw_server_ns = raw_server_ns
    
    def __repr__(self):
        return f"TimingResult(time={self.time_us}µs, correct={self.correct})"

class PycurlHTTPSender(RequestSender):
    def __init__(
        self,
        url: str,
        base_payload: Dict[str, Any],
        timeout_sec: float = 5.0,
        max_workers: int = 300,
        warmup_requests: int = 30,
        baseline_samples: int = 50,
        verbose: bool = True
    ):
        self.url = url.rstrip("/") + "/"
        self.fixed_payload = base_payload.copy()
        self.timeout_sec = timeout_sec
        self.max_workers = max_workers
        self.warmup_requests = warmup_requests
        self.baseline_samples = baseline_samples
        self.verbose = verbose
        
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self._initialized = False
        self._baseline_ns = 0
        self._baseline_lock = threading.Lock()
        
        # רשימה לניקוי curl instances בסוף
        self._curl_instances = []
        self._curl_lock = threading.Lock()

    @staticmethod
    def _get_curl_instance():
        if not hasattr(_thread_local, 'curl'):
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
            _thread_local.curl = c
        return _thread_local.curl

    def _warmup_and_baseline(self):
        # warmup
        warmup_futures = []
        for i in range(self.warmup_requests):
            payload = {"password": f"warm{i:04d}"}
            warmup_futures.append(
                self.executor.submit(self._single_request_raw, payload)
            )
        
        for f in warmup_futures:
            try:
                f.result()
            except Exception as e:
                self._log(f"⚠️  שגיאה ב-warmup: {e}")

        # מדידת baseline – בקשות על סיסמה שגויה ברורה
        baseline_times = []
        failed_count = 0
        
        for _ in range(self.baseline_samples):
            result = self._single_request_raw({"password": "definitely_wrong_baseline"})
            if result.raw_server_ns > 0:
                baseline_times.append(result.raw_server_ns)
            else:
                failed_count += 1

        if not baseline_times:
            self._log("⚠️  כל בקשות ה-baseline נכשלו! baseline יהיה 0")
            self._baseline_ns = 0
            return

        if failed_count > 0:
            self._log(f"⚠️  {failed_count}/{self.baseline_samples} בקשות baseline נכשלו")

        # שימוש ב-P25 (percentile 25) - עמיד יותר לחריגים מאשר מדיאן
        baseline_times.sort()
        self._baseline_ns = baseline_times[len(baseline_times) // 4]
        
        stats = TimingStats([t // 1000 for t in baseline_times])
        self._log(f"✓ Baseline חושב: {self._baseline_ns} ns ({self._baseline_ns // 1000} µs)")
        self._log(f"  סטטיסטיקות baseline: {stats}")

    def _single_request_raw(self, variable_payload: Dict[str, Any]) -> TimingResult:
        """בקשה בודדת – מחזירה TimingResult"""
        payload = self.fixed_payload.copy()
        payload.update(variable_payload)

        url = self.url + "?" + urllib.parse.urlencode(payload)

        buffer = BytesIO()
        c = self._get_curl_instance()
        
        # שמירת reference ל-curl instance לניקוי מאוחר יותר
        with self._curl_lock:
            if c not in self._curl_instances:
                self._curl_instances.append(c)
        
        c.setopt(pycurl.URL, url)
        c.setopt(pycurl.WRITEFUNCTION, buffer.write)

        try:
            c.perform()
        except pycurl.error as e:
            if self.verbose:
                self._log(f"⚠️  pycurl error: {e}")
            c.reset()
            return TimingResult(body="", time_us=0, correct=False, raw_server_ns=0)

        # זמנים מדויקים מ-libcurl
        pretransfer = c.getinfo(pycurl.PRETRANSFER_TIME)
        starttransfer = c.getinfo(pycurl.STARTTRANSFER_TIME)
        status = c.getinfo(pycurl.RESPONSE_CODE)

        body = buffer.getvalue().strip().decode('utf-8', errors='ignore')

        # חישוב זמן עיבוד שרת נקי
        server_ns = int((starttransfer - pretransfer) * 1_000_000_000)

        # הפחתת baseline
        with self._baseline_lock:
            corrected_ns = max(0, server_ns - self._baseline_ns)
        
        corrected_us = corrected_ns // 1000

        # התאם את תנאי ההצלחה לפורמט של השרת שלך
        is_correct = (status == 200 and body.lower() in {"1", "true", "ok", "success"})

        c.reset()

        return TimingResult(
            body=body,
            time_us=corrected_us,
            correct=is_correct,
            raw_server_ns=server_ns
        )

    def init(self):
        """חייב לקרוא לפני שימוש ראשון – מבצע warmup ו-baseline"""
        if not self._initialized:
            self._warmup_and_baseline()
            self._initialized = True
            self._log("✓ אתחול הושלם בהצלחה")

    def send(self, payload: Dict[str, Any]) -> Tuple[str, int]:
        """
        ממשק סינכרוני – מתאים ללולאות פשוטות
        מחזיר (body, server_processing_time_us_corrected)
        """
        if not self._initialized:
            raise RuntimeError("חייב לקרוא ל-init() לפני שימוש ראשון!")

        result = self._single_request_raw(payload)
        return result.body, result.time_us

    def send_many(
        self, 
        payloads: List[Dict[str, Any]], 
        preserve_order: bool = True
    ) -> List[Tuple[str, int]]:
        if not self._initialized:
            raise RuntimeError("חייב לקרוא ל-init() לפני שימוש ראשון!")

        futures = [
            self.executor.submit(self._single_request_raw, p)
            for p in payloads
        ]

        results = []
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append((result.body, result.time_us))
            except Exception as e:
                self._log(f"⚠️  שגיאה בבקשה: {e}")
                results.append(("", 0))

        return results

    def send_many_detailed(
        self, 
        payloads: List[Dict[str, Any]]
    ) -> List[TimingResult]:
        """
        כמו send_many אבל מחזיר TimingResult מלא עם כל הפרטים
        שימושי לניתוח מתקדם
        """
        if not self._initialized:
            raise RuntimeError("חייב לקרוא ל-init() לפני שימוש ראשון!")

        results = [None] * len(payloads)
        future_to_idx = {
            self.executor.submit(self._single_request_raw, p): i 
            for i, p in enumerate(payloads)
        }
        
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception as e:
                self._log(f"⚠️  שגיאה בבקשה {idx}: {e}")
                results[idx] = TimingResult("", 0, False, 0)
        
        return results
    
    def close_sessions(self):
        """סגירת כל ה-curl handles וה-executor"""
        self._log("סוגר חיבורים...")
        
        # סגירת executor
        self.executor.shutdown(wait=True)
        
        # ניקוי curl instances
        with self._curl_lock:
            for curl in self._curl_instances:
                try:
                    curl.close()
                except:
                    pass
            self._curl_instances.clear()
        
        self._log("✓ כל החיבורים נסגרו")

    def __enter__(self):
        """תמיכה ב-context manager"""
        self.init()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """תמיכה ב-context manager"""
        self.close_sessions()
        return False
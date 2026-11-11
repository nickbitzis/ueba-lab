"""Seeded synthetic company: a directory, an HR feed, and 90 days of security logs with planted scenarios.

Everything here is raw source data keyed by real employee ids. The analytics layer never reads it directly:
`privacy.ingest` pseudonymizes it first.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import NamedTuple

COMPANY = "Corvane Analytics"
START = date(2026, 7, 3)
DAYS = 90
WARMUP = 28

# code: (city, country, lat, lon, utc offset in hours)
CITIES: dict[str, tuple[str, str, float, float, int]] = {
    "BOS": ("Boston", "US", 42.36, -71.06, -4),
    "AUS": ("Austin", "US", 30.27, -97.74, -5),
    "DUB": ("Dublin", "IE", 53.35, -6.26, 1),
    "WAW": ("Warsaw", "PL", 52.23, 21.01, 2),
    "SIN": ("Singapore", "SG", 1.35, 103.82, 8),
    "IAD": ("Ashburn data center", "US", 39.04, -77.49, -4),
    "LON": ("London", "GB", 51.51, -0.13, 1),
    "TYO": ("Tokyo", "JP", 35.68, 139.69, 9),
    "TOR": ("Toronto", "CA", 43.65, -79.38, -4),
    "SAO": ("Sao Paulo", "BR", -23.55, -46.63, -3),
    "SYD": ("Sydney", "AU", -33.87, 151.21, 10),
    "REK": ("Reykjavik", "IS", 64.15, -21.94, 0),
}

# team: (role weights, offices)
TEAMS: dict[str, tuple[dict[str, int], list[str]]] = {
    "eng-platform": ({"engineer": 8, "sre": 3, "manager": 1}, ["BOS", "WAW"]),
    "eng-payments": ({"engineer": 8, "sre": 1, "manager": 1}, ["BOS", "DUB"]),
    "eng-data": ({"engineer": 6, "data_analyst": 3, "manager": 1}, ["AUS", "WAW"]),
    "eng-mobile": ({"engineer": 7, "manager": 1}, ["AUS", "SIN"]),
    "finance-accounting": ({"accountant": 8, "manager": 1}, ["BOS"]),
    "finance-fpa": ({"fin_analyst": 6, "manager": 1}, ["BOS", "DUB"]),
    "sales-na": ({"sales_rep": 10, "manager": 1}, ["AUS", "BOS"]),
    "sales-emea": ({"sales_rep": 8, "manager": 1}, ["DUB", "WAW"]),
    "sales-apac": ({"sales_rep": 5, "manager": 1}, ["SIN"]),
    "support": ({"support_agent": 12, "manager": 1}, ["DUB", "AUS", "SIN"]),
    "hr": ({"hr_partner": 5, "manager": 1}, ["BOS"]),
    "legal": ({"counsel": 4, "manager": 1}, ["BOS", "DUB"]),
    "it": ({"it_admin": 5, "helpdesk": 5, "manager": 1}, ["BOS", "WAW"]),
    "security": ({"security_analyst": 5, "manager": 1}, ["BOS"]),
    "marketing": ({"marketer": 6, "manager": 1}, ["AUS", "DUB"]),
}
SENSITIVE_PREFIXES = ("finance-", "hr/", "legal/", "security/")


@dataclass(frozen=True)
class RoleProfile:
    files: float  # mean file reads per active day
    emails: float
    ext: float  # share of email that goes to external recipients
    repo: float = 0.0  # mean repo events per day
    cloud: float = 0.0  # cloud console actions per day
    iam: float = 0.0  # privilege changes per day
    acl: float = 0.0  # file share permission changes per day
    vpn: float = 0.35  # chance of working remotely on VPN


ROLES: dict[str, RoleProfile] = {
    "engineer": RoleProfile(14, 18, 0.03, repo=4, cloud=10, iam=0.03),
    "sre": RoleProfile(10, 15, 0.03, repo=3, cloud=30, iam=0.4),
    "data_analyst": RoleProfile(25, 15, 0.04, repo=1.5, cloud=6),
    "accountant": RoleProfile(35, 30, 0.10),
    "fin_analyst": RoleProfile(30, 25, 0.08),
    "sales_rep": RoleProfile(12, 55, 0.45),
    "support_agent": RoleProfile(10, 70, 0.35),
    "hr_partner": RoleProfile(20, 35, 0.10),
    "counsel": RoleProfile(18, 30, 0.25),
    "it_admin": RoleProfile(10, 20, 0.04, cloud=15, iam=3, acl=4),
    "helpdesk": RoleProfile(6, 30, 0.05, acl=1),
    "security_analyst": RoleProfile(12, 20, 0.05, cloud=12),
    "marketer": RoleProfile(15, 40, 0.30),
    "manager": RoleProfile(12, 45, 0.15),
}
SERVICE_TYPES = ["svc-ci", "svc-etl", "svc-backup", "svc-deploy", "svc-notify"]


class Event(NamedTuple):
    ts: int  # minutes since START 00:00 UTC
    day: int  # business day the event belongs to
    user: str  # employee or service account id
    source: str  # idp, vpn, files, repo, email, cloud, badge
    action: str
    resource: str
    city: str
    device: str
    count: int = 1
    mb: float = 0.0


@dataclass
class Person:
    uid: str
    name: str
    email: str
    role: str
    team: str
    office: str
    manager: str | None
    kind: str = "employee"  # or "service"
    contractor: bool = False
    end_day: int | None = None  # contract end or last day; no activity after unless planted
    start_minute: int = 540  # local start of the working day
    devices: list[str] = field(default_factory=list)
    shares: list[str] = field(default_factory=list)
    repos: list[str] = field(default_factory=list)
    team_changes: list[tuple[int, str]] = field(default_factory=list)

    def team_on(self, day: int) -> str:
        team = self.team
        for d, t in self.team_changes:
            if day >= d:
                team = t
        return team


@dataclass
class HREvent:
    kind: str  # resignation, contract_end, travel, team_change
    uid: str
    start: int
    end: int
    detail: dict = field(default_factory=dict)


@dataclass
class Scenario:
    sid: str
    kind: str
    uid: str
    start: int
    end: int
    malicious: bool
    description: str


@dataclass
class World:
    people: dict[str, Person]
    events: list[Event]
    hr: list[HREvent]
    scenarios: list[Scenario]
    days: int = DAYS
    warmup: int = WARMUP
    start: date = START
    company: str = COMPANY

    def date_of(self, day: int) -> str:
        return (self.start + timedelta(days=day)).isoformat()


FIRST = ["Ava", "Ben", "Chloe", "Dan", "Ema", "Finn", "Gia", "Hugo", "Iris", "Jon", "Kai", "Lena", "Milo", "Nora",
         "Owen", "Pia", "Quin", "Rosa", "Sam", "Tara", "Uma", "Vic", "Wren", "Xia", "Yara", "Zed"]
LAST = ["Abara", "Brandt", "Castell", "Doyle", "Eklund", "Farrow", "Galvin", "Hale", "Ishii", "Jaskar", "Kovac",
        "Lindqvist", "Moreau", "Novak", "Okafor", "Price", "Quarry", "Rourke", "Salo", "Tamm", "Varga", "Wexler"]


def is_workday(day: int) -> bool:
    return (START + timedelta(days=day)).weekday() < 5


def next_workday(day: int) -> int:
    while not is_workday(day):
        day += 1
    return day


def quarter_end_days() -> range:
    """The last five business days before the quarter closes on Sep 30 (day 89)."""
    days = [d for d in range(DAYS) if is_workday(d)][-5:]
    return range(days[0], DAYS)


def team_shares(team: str) -> list[str]:
    names = ["shared", "projects", "reports", "archive", "planning", "reviews"]
    return [f"{team}/{n}" for n in names]


def team_repos(team: str) -> list[str]:
    return [f"{team}-{n}" for n in ("api", "web", "jobs", "infra", "sdk", "tools", "docs", "models")] \
        if team.startswith("eng-") else []


COMPANY_SHARES = ["all/handbook", "all/templates", "all/townhall"]


def is_sensitive(resource: str) -> bool:
    return resource.split(":", 1)[-1].startswith(SENSITIVE_PREFIXES)


def build_directory(rng: random.Random, employees: int, services: int) -> dict[str, Person]:
    people: dict[str, Person] = {}
    total_w = sum(sum(w.values()) for w, _ in TEAMS.values())
    n = 0
    for team, (weights, offices) in TEAMS.items():
        size = max(len(weights) * 3, round(employees * sum(weights.values()) / total_w))
        roles = [r for r, w in weights.items() if r != "manager" for _ in range(w)]
        mgr_uid = None
        for k in range(size):
            n += 1
            uid = f"E{10000 + n}"
            role = "manager" if k == 0 else rng.choice(roles)
            first, last = rng.choice(FIRST), rng.choice(LAST)
            office = rng.choice(offices)
            shares = team_shares(team)
            p = Person(
                uid=uid, name=f"{first} {last}", email=f"{first.lower()}.{last.lower()}{n}@corvane.example",
                role=role, team=team, office=office, manager=mgr_uid,
                contractor=role in ("engineer", "support_agent") and rng.random() < 0.06,
                start_minute=rng.choice([450, 480, 510, 540, 570, 600]) + rng.randint(-10, 10),
                devices=[f"lt-{n:05d}"] + ([f"ph-{n:05d}"] if rng.random() < 0.7 else []),
                shares=rng.sample(shares, 4) + COMPANY_SHARES,
                repos=rng.sample(team_repos(team), 5) if team_repos(team) else [],
            )
            if k == 0:
                mgr_uid = uid
            people[uid] = p
    teams = list(TEAMS)
    for k in range(services):
        stype = SERVICE_TYPES[k % len(SERVICE_TYPES)]
        team = teams[(k * 7) % len(teams)]
        if stype in ("svc-ci", "svc-deploy"):
            team = rng.choice([t for t in teams if t.startswith("eng-")])
        uid = f"{stype}-{k:03d}"
        repos = [r for t in teams for r in team_repos(t)]
        people[uid] = Person(
            uid=uid, name=uid, email=f"{uid}@svc.corvane.example", role=stype, team=team, office="IAD",
            manager=None, kind="service", devices=[f"host-{k:03d}"],
            shares=rng.sample(team_shares(team), 3),
            repos=rng.sample(repos, 6) if stype == "svc-ci" else [],
        )
    return people


class Gen:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.events: list[Event] = []

    def ts(self, day: int, local_minute: float, city: str) -> int:
        return int(day * 1440 + local_minute - CITIES[city][4] * 60)

    def emit(self, p: Person, day: int, local_minute: float, source: str, action: str, resource: str,
             city: str | None = None, device: str | None = None, count: int = 1, mb: float = 0.0) -> None:
        city = city or p.office
        self.events.append(Event(self.ts(day, local_minute, city), day, p.uid, source, action, resource, city,
                                 device or p.devices[0], int(count), round(mb, 2)))

    def lognorm(self, mean: float, sigma: float = 0.45) -> float:
        return mean * math.exp(self.rng.gauss(0, sigma) - sigma * sigma / 2)

    # ------------------------------------------------------------------ routine behavior
    def employee_day(self, p: Person, day: int, city: str | None = None, volume: float = 1.0,
                     extra_hours: float = 0.0, light: bool = False) -> None:
        rng = self.rng
        prof = ROLES[p.role]
        city = city or p.office
        start = p.start_minute + rng.gauss(0, 20)
        end = start + 510 + rng.gauss(0, 35) + extra_hours * 60
        if light:
            end = start + rng.uniform(30, 120)
        busy = self.lognorm(1.0, 0.3) * volume

        def t() -> float:
            return rng.uniform(start, end)

        team = p.team_on(day)
        remote = city != p.office or rng.random() < prof.vpn or light
        dev = p.devices[0] if rng.random() < 0.9 or len(p.devices) == 1 else p.devices[1]
        apps = ["mail", "chat", "wiki"] + (["git"] if p.repos else []) + (["cloud"] if prof.cloud else [])
        for k in range(1 if light else rng.choice([1, 2, 2, 3])):
            self.emit(p, day, start if k == 0 else t(), "idp", "signin", f"app:{rng.choice(apps)}", city, dev)
        if rng.random() < 0.03:
            self.emit(p, day, start - 1, "idp", "signin_fail", "app:mail", city, dev)
        if remote:
            self.emit(p, day, start + 1, "vpn", "connect", "vpn:corp", city, dev, mb=self.lognorm(300 * busy))
        elif rng.random() < 0.97:
            self.emit(p, day, start - 5, "badge", "entry", f"site:{p.office}", city, "badge")
        n_reads = max(1, round(self.lognorm(prof.files * busy * (0.3 if light else 1.0))))
        picks = rng.sample(p.shares, min(len(p.shares), rng.choice([1, 2, 2, 3])))
        if rng.random() < 0.03:
            picks.append(rng.choice(team_shares(team)))
        for share in picks:
            c = max(1, round(n_reads / len(picks)))
            self.emit(p, day, t(), "files", "read", f"share:{share}", city, dev, c, c * self.lognorm(0.8))
        if prof.acl and rng.random() < 0.7:
            c = max(1, round(self.lognorm(prof.acl)))
            self.emit(p, day, t(), "files", "acl_change", f"share:{rng.choice(team_shares(rng.choice(list(TEAMS))))}",
                      city, dev, c)
        if p.repos and not light:
            n = round(self.lognorm(prof.repo * busy))
            for repo in rng.sample(p.repos, min(len(p.repos), max(1, n // 2))) if n else []:
                self.emit(p, day, t(), "repo", "push" if rng.random() < 0.75 else "clone", f"repo:{repo}", city, dev,
                          max(1, round(n / 2)))
        emails = max(1, round(self.lognorm(prof.emails * busy * (0.3 if light else 1.0))))
        ext = round(emails * prof.ext * self.lognorm(1.0, 0.3))
        self.emit(p, day, t(), "email", "send", "mail:internal", city, dev, emails - min(ext, emails - 1),
                  self.lognorm(0.1 * emails))
        if ext:
            self.emit(p, day, t(), "email", "send", "mail:external", city, dev, ext, self.lognorm(0.3 * ext))
        if prof.cloud and not light:
            c = max(1, round(self.lognorm(prof.cloud * busy)))
            self.emit(p, day, t(), "cloud", "action", f"cloud:{team}", city, dev, c)
            if rng.random() < min(0.95, prof.iam):
                self.emit(p, day, t(), "cloud", "iam_grant", f"cloud:{team}", city, dev,
                          max(1, round(self.lognorm(max(1.0, prof.iam)))))

    def service_day(self, p: Person, day: int) -> None:
        rng = self.rng
        host = p.devices[0]
        for _ in range(6):
            self.emit(p, day, rng.uniform(0, 1439), "idp", "token", "app:api", "IAD", host)
        if p.role == "svc-ci":
            for repo in rng.sample(p.repos, 3):
                self.emit(p, day, rng.uniform(0, 1439), "repo", "clone", f"repo:{repo}", "IAD", host,
                          max(1, round(self.lognorm(12))))
        elif p.role in ("svc-etl", "svc-backup"):
            for share in p.shares:
                c = max(1, round(self.lognorm(80 if p.role == "svc-etl" else 40, 0.25)))
                self.emit(p, day, rng.uniform(0, 1439), "files", "read", f"share:{share}", "IAD", host, c,
                          c * (5 if p.role == "svc-backup" else 0.5))
        elif p.role == "svc-deploy":
            self.emit(p, day, rng.uniform(0, 1439), "cloud", "action", f"cloud:{p.team}", "IAD", host,
                      max(1, round(self.lognorm(40, 0.3))))
        elif p.role == "svc-notify":
            self.emit(p, day, rng.uniform(0, 1439), "email", "send", "mail:internal", "IAD", host,
                      max(1, round(self.lognorm(200, 0.25))))


def _pick(rng: random.Random, people: dict[str, Person], used: set[str], **want) -> Person:
    pool = [p for p in people.values() if p.uid not in used and all(getattr(p, k) == v for k, v in want.items())]
    p = rng.choice(sorted(pool, key=lambda x: x.uid))
    used.add(p.uid)
    return p


def generate(seed: int = 7, scale: float = 1.0, days: int = DAYS) -> World:
    """Build the company and its logs. scale=1.0 is about 1,500 employees and 200 service accounts."""
    rng = random.Random(seed)
    people = build_directory(rng, round(1500 * scale), max(15, round(200 * scale)))
    hr: list[HREvent] = []
    scenarios: list[Scenario] = []
    used: set[str] = set()
    employees = [p for p in people.values() if p.kind == "employee"]

    # Ordinary contractor end dates: most run past the window, a few end on time and go quiet.
    for p in employees:
        if p.contractor:
            p.end_day = rng.choice([None, None, None, rng.randint(35, 80)])
            if p.end_day is not None:
                hr.append(HREvent("contract_end", p.uid, p.end_day, p.end_day))
                used.add(p.uid)

    # ---------------------------------------------------------- planted malicious scenarios
    s_exfil = _pick(rng, people, used, role="engineer", team="eng-data", contractor=False)
    notice, last = next_workday(52), next_workday(74)
    s_exfil.end_day = last
    hr.append(HREvent("resignation", s_exfil.uid, notice, last))
    exfil_start = next_workday(60)
    scenarios.append(Scenario("S1", "departing_bulk_download", s_exfil.uid, exfil_start, last, True,
                              "Engineer who resigned on day 52 bulk-downloads files and clones other teams' repos "
                              "in the last two weeks before leaving."))

    s_comp = _pick(rng, people, used, role="sales_rep", team="sales-na", office="AUS")
    comp_day = next_workday(63)
    scenarios.append(Scenario("S2", "compromised_account", s_comp.uid, comp_day, comp_day + 1, True,
                              "Sales account signs in from Reykjavik two hours after an Austin sign-in, resets MFA, "
                              "then opens finance shares and the cloud console for the first time."))

    s_svc = _pick(rng, people, used, kind="service", role="svc-etl")
    svc_day = next_workday(58)
    scenarios.append(Scenario("S3", "service_account_interactive", s_svc.uid, svc_day, svc_day + 1, True,
                              "ETL service account used for an interactive browser sign-in from an office laptop, "
                              "then reads HR shares."))

    s_share = _pick(rng, people, used, role="support_agent", office="DUB", contractor=False)
    share_start = next_workday(50)
    scenarios.append(Scenario("S4", "credential_sharing", s_share.uid, share_start, 70, True,
                              "Dublin support account is also used from Austin on an unknown device on the same days."))

    pool = [p for p in employees if p.uid not in used and p.role == "support_agent"]
    s_con = sorted(pool, key=lambda x: x.uid)[0]
    used.add(s_con.uid)
    s_con.contractor, s_con.end_day = True, 60
    hr.append(HREvent("contract_end", s_con.uid, 60, 60))
    con_start = next_workday(61)
    scenarios.append(Scenario("S5", "contractor_after_end_date", s_con.uid, con_start, 70, True,
                              "Contractor whose contract ended on day 60 keeps signing in and reading files."))

    s_admin = _pick(rng, people, used, role="it_admin")
    admin_day = next_workday(66)
    scenarios.append(Scenario("S6", "admin_mass_permission_change", s_admin.uid, admin_day, admin_day, True,
                              "IT admin makes 340 share permission changes and 120 cloud role grants at 2 a.m."))

    # ---------------------------------------------------------- benign surprises
    trips: dict[str, tuple[int, int, str]] = {}
    for k in range(max(4, round(15 * scale))):
        p = _pick(rng, people, used, kind="employee")
        dest = rng.choice(["LON", "TYO", "TOR", "SAO", "SYD"])
        if CITIES[dest][1] == CITIES[p.office][1]:
            dest = "TYO"
        start = next_workday(rng.randint(32, 80))
        end = min(DAYS - 1, start + rng.randint(3, 6))
        trips[p.uid] = (start, end, dest)
        hr.append(HREvent("travel", p.uid, start, end, {"city": dest, "country": CITIES[dest][1], "approved": True}))
        scenarios.append(Scenario(f"B-travel-{k + 1}", "approved_travel", p.uid, start, end, False,
                                  f"Approved trip to {CITIES[dest][0]}."))

    reorg_day = next_workday(45)
    movers = [p for p in employees if p.team == "eng-payments" and p.role == "engineer" and p.uid not in used]
    movers = sorted(movers, key=lambda x: x.uid)[: max(5, round(20 * scale))]
    for p in movers:
        used.add(p.uid)
        p.team_changes.append((reorg_day, "eng-platform"))
        hr.append(HREvent("team_change", p.uid, reorg_day, reorg_day, {"from": "eng-payments", "to": "eng-platform"}))
        scenarios.append(Scenario(f"B-reorg-{p.uid}", "team_reorg", p.uid, reorg_day, reorg_day + 14, False,
                                  "Moved from eng-payments to eng-platform in a reorg."))

    mover_ids = {p.uid for p in movers}
    qe = quarter_end_days()
    finance = [p for p in employees if p.team.startswith("finance-") and p.uid not in used]
    for p in finance:
        scenarios.append(Scenario(f"B-qe-{p.uid}", "quarter_end_finance", p.uid, qe.start, qe.stop - 1, False,
                                  "Quarter-end close: file volume and hours rise for all of finance."))

    # Ordinary resignations with ordinary behavior, so a resignation alone is not a signal.
    for p in rng.sample(sorted([p for p in employees if p.uid not in used], key=lambda x: x.uid), 6):
        used.add(p.uid)
        n_day, l_day = next_workday(rng.randint(40, 60)), next_workday(rng.randint(70, 85))
        p.end_day = l_day
        hr.append(HREvent("resignation", p.uid, n_day, l_day))

    # ---------------------------------------------------------- unlabeled background noise
    # Real logs are messy. None of this is planted as a scenario, so any case it causes counts as a false positive:
    # trips nobody filed with HR, laptop refreshes, crunch days with late nights, and helping another team.
    for p in rng.sample(sorted([p for p in employees if p.uid not in used], key=lambda x: x.uid),
                        max(2, round(6 * scale))):
        start = next_workday(rng.randint(30, 80))
        dest = rng.choice([c for c in ("LON", "TOR", "TYO", "SAO") if CITIES[c][1] != CITIES[p.office][1]])
        trips[p.uid] = (start, min(DAYS - 1, start + rng.randint(2, 5)), dest)
    refresh = {p.uid: rng.randint(WARMUP, DAYS - 1) for p in employees if rng.random() < 0.05}
    teams = list(TEAMS)

    # ---------------------------------------------------------- routine logs
    g = Gen(rng)
    for day in range(days):
        work = is_workday(day)
        for p in people.values():
            if p.kind == "service":
                g.service_day(p, day)
                continue
            if p.end_day is not None and day > p.end_day:
                continue
            if day >= reorg_day and p.uid in mover_ids and not p.shares[0].startswith("eng-platform"):
                p.shares = rng.sample(team_shares("eng-platform"), 4) + COMPANY_SHARES
                p.repos = rng.sample(team_repos("eng-platform"), 5)
            if refresh.get(p.uid) == day:
                p.devices[0] = f"lt-new-{p.uid[1:]}"
            trip = trips.get(p.uid)
            city = trip[2] if trip and trip[0] < day <= trip[1] else None
            if not work:
                if rng.random() < 0.08:
                    g.employee_day(p, day, city=city, light=True)
                continue
            if rng.random() < 0.04:
                continue  # time off
            if trip and day == trip[0]:
                # Flight day: morning at home, then a sign-in after landing. Speed stays under airliner speed.
                g.employee_day(p, day, light=True)
                dist = haversine_km(p.office, trip[2])
                landed = g.ts(day, p.start_minute + 120 + dist / 800 * 60 + 90, p.office)  # home clock to UTC
                g.events.append(Event(landed, day, p.uid, "idp", "signin", "app:mail", trip[2], p.devices[0]))
                continue
            qe_boost = p.team_on(day).startswith("finance-") and day in qe
            crunch = rng.random() < 0.004
            g.employee_day(p, day, city=city, volume=4.0 if qe_boost else 5.0 if crunch else 1.0,
                           extra_hours=3 if qe_boost else 4 if crunch else 0)
            if rng.random() < 0.003:
                for share in rng.sample(team_shares(rng.choice(teams)), 2):
                    c = rng.randint(5, 30)
                    g.emit(p, day, p.start_minute + 300, "files", "read", f"share:{share}", city, count=c, mb=c)

    _plant(g, people, rng, s_exfil, exfil_start, last, s_comp, comp_day, s_svc, svc_day, s_share, share_start,
           s_con, con_start, s_admin, admin_day)
    g.events.sort(key=lambda e: e.ts)
    return World(people, g.events, hr, scenarios, days=days)


def _plant(g: Gen, people, rng, s_exfil, exfil_start, last, s_comp, comp_day, s_svc, svc_day, s_share, share_start,
           s_con, con_start, s_admin, admin_day) -> None:
    other_shares = [s for t in ("eng-platform", "eng-payments", "finance-fpa", "legal") for s in team_shares(t)]
    other_repos = [r for t in ("eng-platform", "eng-payments", "eng-mobile") for r in team_repos(t)]
    # S1: departing employee, late evening bulk downloads
    for day in range(exfil_start, last):
        if not is_workday(day):
            continue
        for share in rng.sample(s_exfil.shares[:4], 3) + rng.sample(other_shares, 2):
            c = rng.randint(120, 260)
            g.emit(s_exfil, day, rng.uniform(1230, 1380), "files", "read", f"share:{share}", count=c, mb=c * 3.5)
        for repo in rng.sample(other_repos, 5):
            g.emit(s_exfil, day, rng.uniform(1230, 1380), "repo", "clone", f"repo:{repo}", count=3)
        g.emit(s_exfil, day, rng.uniform(1300, 1400), "email", "send", "mail:external", count=8, mb=180)
    # S2: compromised account
    p = s_comp
    g.emit(p, comp_day, 545, "idp", "signin", "app:mail", "AUS")
    foreign = 545 + 160  # local Austin minutes; same instant expressed in Austin time
    dev = "unknown-7f3a"
    for day in (comp_day, comp_day + 1):
        off = 0 if day == comp_day else -300
        g.events.append(Event(g.ts(day, foreign + off, "AUS"), day, p.uid, "idp", "signin", "app:mail", "REK", dev))
        if day == comp_day:
            g.events.append(Event(g.ts(day, foreign + 25, "AUS"), day, p.uid, "idp", "mfa_reset", "app:idp", "REK",
                                  dev))
        for share in ("finance-fpa/reports", "finance-accounting/planning", "finance-accounting/reports"):
            g.events.append(Event(g.ts(day, foreign + rng.uniform(30, 120), "AUS"), day, p.uid, "files", "read",
                                  f"share:{share}", "REK", dev, rng.randint(60, 120), 150.0))
        g.events.append(Event(g.ts(day, foreign + 70, "AUS"), day, p.uid, "cloud", "action", "cloud:console", "REK",
                              dev, 14))
        g.events.append(Event(g.ts(day, foreign + 90, "AUS"), day, p.uid, "email", "send", "mail:external", "REK",
                              dev, 40, 60.0))
    # S3: service account used interactively from an office laptop
    for day in (svc_day, svc_day + 1):
        g.emit(s_svc, day, 610, "idp", "signin", "app:wiki", "BOS", "lt-unregistered")
        for share in ("hr/reports", "hr/planning"):
            g.emit(s_svc, day, 640, "files", "read", f"share:{share}", "BOS", "lt-unregistered", 45, 40)
    # S4: credential sharing, a second person in Austin on another device
    for day in range(share_start, 71):
        if is_workday(day) and rng.random() < 0.8:
            for _ in range(2):
                g.emit(s_share, day, rng.uniform(560, 900), "idp", "signin", "app:mail", "AUS", "lt-other-22")
            g.emit(s_share, day, 700, "files", "read", "share:support/shared", "AUS", "lt-other-22", 15, 10)
    # S5: contractor keeps working after the end date at a lower level
    for day in range(con_start, 71):
        if is_workday(day):
            g.employee_day(s_con, day, volume=0.6)
    # S6: admin mass permission changes at 2 a.m.
    shares = [s for t in TEAMS for s in team_shares(t)]
    for k, share in enumerate(rng.sample(shares, 40)):
        g.emit(s_admin, admin_day, rng.uniform(120, 180), "files", "acl_change", f"share:{share}", count=8 + k % 2)
    g.emit(s_admin, admin_day, 150, "cloud", "iam_grant", "cloud:it", count=120)
    g.emit(s_admin, admin_day, 118, "idp", "signin", "app:cloud")


def haversine_km(a: str, b: str) -> float:
    _, _, la1, lo1, _ = CITIES[a]
    _, _, la2, lo2, _ = CITIES[b]
    p1, p2 = math.radians(la1), math.radians(la2)
    dp, dl = p2 - p1, math.radians(lo2 - lo1)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(h))

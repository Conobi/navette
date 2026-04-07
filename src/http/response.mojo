from .status import StatusCode
from .version import Version
from .headers import Headers
from .body import BodyFrame

struct Response(Movable):
    var status: StatusCode
    var reason: String
    var version: Version
    var headers: Headers
    var body: List[BodyFrame]

    def __init__(out self):
        self.status = StatusCode()
        self.reason = String("")
        self.version = Version.http_1_1()
        self.headers = Headers()
        self.body = List[BodyFrame]()

    def __init__(out self, *, deinit take: Self):
        self.status = take.status^
        self.reason = take.reason^
        self.version = take.version^
        self.headers = take.headers^
        self.body = take.body^

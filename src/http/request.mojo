from .method import Method
from .version import Version
from .headers import Headers
from .body import BodyFrame

struct Request(Movable):
    var method: Method
    var target: String
    var version: Version
    var headers: Headers
    var body: List[BodyFrame]

    def __init__(out self):
        self.method = Method()
        self.target = String("")
        self.version = Version.http_1_1()
        self.headers = Headers()
        self.body = List[BodyFrame]()

    def __init__(out self, *, deinit take: Self):
        self.method = take.method^
        self.target = take.target^
        self.version = take.version^
        self.headers = take.headers^
        self.body = take.body^

# tests/fuzz/lib/report.mojo
#
# Aggregator + finisher for fuzz-harness results.


struct ObserveResult(Copyable, Movable):
    """The output of a single property check."""

    var agreed: Bool
    var detail: String   # error/observation summary if !agreed

    def __init__(out self, agreed: Bool, detail: String = String("")):
        self.agreed = agreed
        self.detail = detail

    def __init__(out self, *, deinit take: Self):
        self.agreed = take.agreed
        self.detail = take.detail^


struct FuzzReport(Movable):
    var harness: String
    var seed: UInt64
    var iters: Int
    var observed: Int
    var disagreements: Int
    var first_disagreement: String  # detail string; empty if none

    def __init__(out self, harness: String, seed: UInt64, iters: Int):
        self.harness = harness
        self.seed = seed
        self.iters = iters
        self.observed = 0
        self.disagreements = 0
        self.first_disagreement = String("")

    def __init__(out self, *, deinit take: Self):
        self.harness = take.harness^
        self.seed = take.seed
        self.iters = take.iters
        self.observed = take.observed
        self.disagreements = take.disagreements
        self.first_disagreement = take.first_disagreement^

    def observe(mut self, result: ObserveResult):
        self.observed += 1
        if not result.agreed:
            self.disagreements += 1
            if self.first_disagreement.byte_length() == 0:
                self.first_disagreement = result.detail

    def finish(self) raises:
        print("harness:", self.harness)
        print("seed:", hex(Int(self.seed)))
        print("observed:", self.observed, "disagreements:", self.disagreements)
        if self.disagreements > 0:
            print("first disagreement:", self.first_disagreement)
            raise "fuzz harness detected " + String(self.disagreements) + " disagreement(s) in " + self.harness

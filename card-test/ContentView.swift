import SwiftUI

struct ContentView: View {
    @StateObject private var exploit = ExploitManager.shared
    @State private var showNoCardsError = false
    @State private var cards: [Card] = []
    @State private var detectedCardsRoot = "not-detected"
    @State private var usedKfsForScan = false
    @State private var offsetInput = ""

    private let helper = ObjcHelper()

    private func joinPath(_ parent: String, _ child: String) -> String {
        if parent.hasSuffix("/") {
            return parent + child
        }
        return parent + "/" + child
    }

    private func listDirectory(_ path: String, usedKfs: inout Bool) -> [String] {
        let fm = FileManager.default
        if let direct = try? fm.contentsOfDirectory(atPath: path) {
            return direct
        }

        guard exploit.kfsReady else {
            return []
        }

        let viaKfs = helper.kfsListDirectory(path)
        if !viaKfs.isEmpty {
            usedKfs = true
        }
        return viaKfs
    }

    private func hasCardBundles(at path: String, usedKfs: inout Bool) -> Bool {
        let entries = listDirectory(path, usedKfs: &usedKfs)
        return entries.contains { $0.hasSuffix("pkpass") }
    }

    private func discoverCardsRoot(usedKfs: inout Bool) -> String? {
        var candidates: [String] = []

        if let detected = exploit.detectedCardsRootPath {
            candidates.append(detected)
        }
        for candidate in exploit.knownCardsRootCandidates where !candidates.contains(candidate) {
            candidates.append(candidate)
        }

        for candidate in candidates where hasCardBundles(at: candidate, usedKfs: &usedKfs) {
            return candidate
        }

        let passContainers = [
            "/var/mobile/Library/Passes",
            "/private/var/mobile/Library/Passes"
        ]

        for container in passContainers {
            let topEntries = listDirectory(container, usedKfs: &usedKfs)

            for primary in ["Cards", "Passes", "Wallet"] where topEntries.contains(primary) {
                let candidate = joinPath(container, primary)
                if hasCardBundles(at: candidate, usedKfs: &usedKfs) {
                    return candidate
                }

                let nestedCards = joinPath(candidate, "Cards")
                if hasCardBundles(at: nestedCards, usedKfs: &usedKfs) {
                    return nestedCards
                }
            }

            for entry in topEntries {
                if entry == "." || entry == ".." {
                    continue
                }

                let lower = entry.lowercased()
                if !(lower.contains("card") || lower.contains("pass") || lower.contains("wallet")) {
                    continue
                }

                let candidate = joinPath(container, entry)
                if hasCardBundles(at: candidate, usedKfs: &usedKfs) {
                    return candidate
                }

                let nestedCards = joinPath(candidate, "Cards")
                if hasCardBundles(at: nestedCards, usedKfs: &usedKfs) {
                    return nestedCards
                }
            }
        }

        return nil
    }

    private func loadCards() {
        cards = getPasses()
    }

    private func getPasses() -> [Card] {
        var usedKfs = false
        guard let cardsRoot = discoverCardsRoot(usedKfs: &usedKfs) else {
            usedKfsForScan = usedKfs
            detectedCardsRoot = "not-detected"
            exploit.setDetectedCardsRootPath(nil)
            return []
        }

        exploit.setDetectedCardsRootPath(cardsRoot)
        detectedCardsRoot = cardsRoot

        var data = [Card]()

        let passes = listDirectory(cardsRoot, usedKfs: &usedKfs).filter { $0.hasSuffix("pkpass") }

        for pass in passes {
            let cardDirectory = joinPath(cardsRoot, pass)
            let files = listDirectory(cardDirectory, usedKfs: &usedKfs)

            if files.contains("cardBackgroundCombined@2x.png") {
                data.append(
                    Card(
                        imagePath: joinPath(cardDirectory, "cardBackgroundCombined@2x.png"),
                        directoryPath: cardDirectory,
                        bundleName: pass,
                        format: "@2x.png"
                    )
                )
            } else if files.contains("cardBackgroundCombined.pdf") {
                data.append(
                    Card(
                        imagePath: joinPath(cardDirectory, "cardBackgroundCombined.pdf"),
                        directoryPath: cardDirectory,
                        bundleName: pass,
                        format: ".pdf"
                    )
                )
            }
        }

        usedKfsForScan = usedKfs
        return data
    }

    private func refreshOffsetInputFromState() {
        if exploit.hasKernprocOffset {
            offsetInput = String(format: "0x%llx", exploit.kernprocOffset)
        }
    }

    private func recheckAndReload() {
        exploit.refreshAccessProbe()
        exploit.refreshKernprocOffsetState()
        loadCards()
    }

    private func runAllAndReload() {
        exploit.runAll { _ in
            recheckAndReload()
            if cards.isEmpty {
                showNoCardsError = true
            }
        }
    }

    private var exploitPanel: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Exploit Engine")
                .font(.system(size: 18, weight: .bold))
                .foregroundColor(.white)

            Text(exploit.statusMessage)
                .font(.system(size: 13, weight: .semibold))
                .foregroundColor(exploit.canApplyCardChanges ? .green : .orange)

            Text(String(
                format: "darksword=%@ | kfs=%@",
                exploit.darkswordReady ? "ready" : "not-ready",
                exploit.kfsReady ? "ready" : "not-ready"
            ))
            .font(.system(size: 12, weight: .regular, design: .monospaced))
            .foregroundColor(.white.opacity(0.85))

            Text(exploit.hasKernprocOffset
                 ? String(format: "kernproc_offset=0x%llx", exploit.kernprocOffset)
                 : "kernproc_offset=missing")
            .font(.system(size: 11, design: .monospaced))
            .foregroundColor(exploit.hasKernprocOffset ? .green.opacity(0.9) : .orange)

            Text("cards_root=\(detectedCardsRoot)")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.white.opacity(0.7))

            Text("scan_mode=\(usedKfsForScan ? "kfs" : "direct")")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.white.opacity(0.7))

            if exploit.darkswordReady {
                Text(String(
                    format: "kernel_base=0x%llx slide=0x%llx",
                    exploit.kernelBase,
                    exploit.kernelSlide
                ))
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.white.opacity(0.7))

                Text(String(
                    format: "our_proc=0x%llx our_task=0x%llx",
                    exploit.ourProc,
                    exploit.ourTask
                ))
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.white.opacity(0.7))
            }

            HStack(spacing: 8) {
                TextField("kernproc offset (hex)", text: $offsetInput)
                    .textFieldStyle(.roundedBorder)

                Button("Set") {
                    if exploit.setKernprocOffset(from: offsetInput) {
                        refreshOffsetInputFromState()
                        recheckAndReload()
                    }
                }
                .foregroundColor(.white)

                Button("Import lara") {
                    _ = exploit.importLaraKernprocOffset()
                    refreshOffsetInputFromState()
                    recheckAndReload()
                }
                .foregroundColor(.white)
            }

            HStack(spacing: 10) {
                Button(exploit.darkswordRunning ? "Running Darksword..." : "Run Darksword") {
                    exploit.runDarksword { _ in
                        recheckAndReload()
                    }
                }
                .disabled(exploit.darkswordRunning || exploit.kfsRunning)
                .foregroundColor(.white)

                Button(exploit.kfsRunning ? "Init KFS..." : "Init KFS") {
                    exploit.initKFS { _ in
                        recheckAndReload()
                    }
                }
                .disabled(exploit.darkswordRunning || exploit.kfsRunning)
                .foregroundColor(.white)

                Button("Run All") {
                    runAllAndReload()
                }
                .disabled(exploit.darkswordRunning || exploit.kfsRunning)
                .foregroundColor(.white)
            }

            ScrollView {
                Text(exploit.logText.isEmpty ? "No logs yet." : exploit.logText)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(Color.green.opacity(0.9))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
            }
            .frame(height: 120)
            .background(Color.white.opacity(0.06))
            .cornerRadius(8)
        }
        .padding(12)
        .background(Color.white.opacity(0.09))
        .cornerRadius(12)
        .padding(.horizontal, 14)
    }

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()

            VStack(spacing: 12) {
                Text("Tap a card to customize")
                    .font(.system(size: 25))
                    .foregroundColor(.white)

                Text("Swipe to view different cards")
                    .font(.system(size: 15))
                    .foregroundColor(.white)

                exploitPanel

                if !cards.isEmpty {
                    TabView {
                        ForEach(cards) { card in
                            CardView(card: card, exploit: exploit)
                        }
                    }
                    .tabViewStyle(PageTabViewStyle(indexDisplayMode: .always))
                    .frame(height: 340)

                    Button("Refresh Cards") {
                        loadCards()
                        if cards.isEmpty {
                            showNoCardsError = true
                        }
                    }
                    .foregroundColor(.white)
                    .padding(.top, 16)
                } else {
                    VStack(spacing: 12) {
                        Text("No Cards Found").foregroundColor(.red)

                        Text("Path: \(detectedCardsRoot)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.white.opacity(0.75))

                        Text(usedKfsForScan ? "Directory scan via KFS" : "Directory scan via direct filesystem")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.white.opacity(0.75))

                        Button("Run All + Scan") {
                            runAllAndReload()
                        }
                        .foregroundColor(.white)

                        Button("Scan Again") {
                            loadCards()
                            if cards.isEmpty {
                                showNoCardsError = true
                            }
                        }
                        .foregroundColor(.white)
                    }
                }
            }
            .alert(isPresented: $showNoCardsError) {
                Alert(
                    title: Text("No Cards Were Found"),
                    message: Text("Last detected cards root: \(detectedCardsRoot)")
                )
            }
        }
        .onAppear {
            recheckAndReload()
            refreshOffsetInputFromState()
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}

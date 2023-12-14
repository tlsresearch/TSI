package tsi.prober;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;
import com.opencsv.CSVReader;
import org.apache.commons.io.FileUtils;
import org.neo4j.driver.*;
import org.neo4j.driver.types.Node;
import tsi.prober.probe.StatefulProbe;
import tsi.prober.probe.StatelessProbe;

import java.io.*;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.neo4j.driver.Values.parameters;
import static tsi.prober.OutputSymbol.*;
import static tsi.prober.InputSymbol.*;

public class Prober {
    Config config;
    String probeFilepath;
    String responseMatchDatabaseDir;
    Map<String, List<String>> probingCache;
    /* ------------------------------------------------------------------------------------------------------------- */
    Connector connector;
    Driver neo4j = null;
    /* ------------------------------------------------------------------------------------------------------------- */
    String outputDir;
    String outputFilename;
    int interval;
    /* ------------------------------------------------------------------------------------------------------------- */
    boolean isEmptyCertAcceptable = true;
    /* ------------------------------------------------------------------------------------------------------------- */

    // Directory to store TLS Messages (.xml)
    String tlsAttackerMessageDir;
    int timeout;
    String tlsVersion;
    List<String> cipherSuiteStrings;
    String compressionMethodString;

    /* ------------------------------------------------------------------------------------------------------------- */

    String username;
    String password;
    String n4jUrl;

    /* ------------------------------------------------------------------------------------------------------------- */

    public static BiMap<String, String> ABBREVIATION = HashBiMap.create(Map.ofEntries(
            Map.entry("CH", "ClientHelloExtendedRenegotiation"),
            Map.entry("CERT", "CertificateEmpty"),
            Map.entry("CKE", "ClientKeyExchange"),
            Map.entry("CKE(bad)", "ClientKeyExchange(bad)"),
            Map.entry("CCS", "ChangeCipherSpec"),
            Map.entry("FIN", "Finished"),
            Map.entry("ALERT", "AlertWarningCloseNotify"),
            Map.entry("APP", "ApplicationData")
    ));

    List<String> statelessProbeRequests = new ArrayList<>();

    /* ------------------------------------------------------------------------------------------------------------- */

    public Prober(String configFilepath, String probeFilepath, String responseMatchDatabaseDir) {
        try {
            this.probeFilepath = probeFilepath;
            this.responseMatchDatabaseDir = responseMatchDatabaseDir;
            this.config = new Config(configFilepath);
            this.probingCache = new HashMap<>();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        /* --------------------------------------------------------------------------------------------------------- */
        outputDir = config.getOutputDir();
        outputFilename = config.getOutputFilename();
        interval = config.getInterval();
        /* --------------------------------------------------------------------------------------------------------- */
        timeout = config.getTimeout();
        tlsVersion = config.getTlsVersion();
        cipherSuiteStrings = List.of(config.getCipherSuites().split(" "));
        compressionMethodString = config.getCompressionMethod();
        tlsAttackerMessageDir = config.getMessageDir();
//        tlsAttackerMessageDir = Objects.requireNonNull(this.getClass().getClassLoader().getResource("/TLSAttackerMessages")).getPath();
        /* --------------------------------------------------------------------------------------------------------- */
        n4jUrl = config.getDatabase();
        username = config.getUsername();
        password = config.getPassword();
        /* --------------------------------------------------------------------------------------------------------- */
        statelessProbeRequests.add("CH");
        statelessProbeRequests.add("CH,CERT,CKE,CCS,FIN,CH");
    }

    private void initialiseNeo4jDriver(String n4jUrl, String username, String password) {
        this.neo4j = GraphDatabase.driver(
                n4jUrl,
                AuthTokens.basic(
                        username,
                        password
                ));
    }

    private void initialiseConnector(String address, int port) {
        try {
            connector = new Connector(address, port, timeout, cipherSuiteStrings, tlsVersion, compressionMethodString, tlsAttackerMessageDir);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

//    public static String sortProbes(String probeFilePath) {
//        List<String> lines = new ArrayList<>();
//        try (BufferedReader reader = new BufferedReader(new FileReader(probeFilePath))) {
//            String line;
//            while ((line = reader.readLine()) != null) {
//                lines.add(line);
//            }
//        } catch (IOException e) {
//            System.err.printf("%25s: %25s: %15s%s%n", "Reading", probeFilePath, " ", "Error");
//            System.exit(1);
//        }
//
//        List<String> sortedLines = new ArrayList<>(lines);
//
//        sortedLines.sort((o1, o2) -> Integer.compare(o2.split(" -> ").length, o1.split(" -> ").length));
//
//        if (sortedLines.equals(lines)) {
//            System.out.printf("%25s: %25s: %15s%s...%n", "Sorting", probeFilePath, " ", "Unnecessary");
//            return probeFilePath;
//        } else {
//
//            Path inputPath = Paths.get(probeFilePath);
//            String outputFilePath = inputPath.getParent().resolve(inputPath.getFileName().toString().replaceFirst("[.][^.]+$", "") + "_sorted.txt").toString();
//            System.out.printf("%25s: %25s: %15s%s...%n", "Sorting", probeFilePath, " ", outputFilePath);
//
//            try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFilePath))) {
//                for (String line : sortedLines) {
//                    writer.write(line);
//                    writer.newLine();
//                }
//            } catch (IOException e) {
//                System.err.printf("%25s: %25s: %15s%s%n", "Writing", outputFilePath, " ", "Error");
//            }
//            return outputFilePath;
//        }
//    }

    /* ------------------------------------------------------------------------------------------------------------- */

    public void identifyMultiTargets(String domainFilepath) {
        String address;
        int port = 443;
        try {
            CSVReader csvReader = new CSVReader(new FileReader(domainFilepath));
            String[] line;
            while ((line = csvReader.readNext()) != null) {
                if (Utils.isReachable(line[0], port, 1000)) {
                    address = line[0];
                    outputFilename = address;
//                    System.out.printf("%25s: %25s: %15s%s...%n", "Connecting", address, " ", "Successful");
                    identifyOneTarget(address, port);
                    System.out.println("--------------------------------------------------------------------");
                } else {
                    System.err.printf("%25s: %25s: %15s%s%n", "Connecting", line[0], " ", "Unreachable");
                    System.err.printf("%25s: %25s: %15s%s%n", "------", "------", " ", "------");
                    System.err.printf("%25s: %25s: %15s%s%n", "------", "------", " ", "------");
                    System.err.println("--------------------------------------------------------------------");
                }
            }
        } catch (IOException e) {
            System.err.printf("%25s: %25s: %15s%s%n", "Reading", domainFilepath, " ", "Error");
            System.exit(1);
        }
    }

    public void identifyOneTarget(String address, int port) {

        isDirExists(outputDir);

        initialiseConnector(address, port);

        LinkedHashMap<String, ArrayList<String>> targetProbingResult;
        LinkedHashMap<String, Integer> matchScores = new LinkedHashMap<>();

        long costTime;
        long startTime = System.currentTimeMillis();

        if (!isHelloSuccessful()) {
            return;
        }

        try {
            targetProbingResult = probing();
        } catch (Exception e) {
            System.err.printf("%25s: %25s: %15s%s%n", "Probing", connector.getTargetHostname(), " ", "Failed");
            return;
        }
        long endTime = System.currentTimeMillis();
        costTime = endTime - startTime;
        System.out.printf("%25s: %25s: %15s%s...%n", "Probing", connector.getTargetHostname(), " ", "Finished");

        File dir = new File(responseMatchDatabaseDir);
        File[] files = dir.listFiles();
        for (File file : files) {
            JSONObject tls = readResponseMatchFile(file);
            int score = responseMatch(targetProbingResult, tls);
            matchScores.put(file.getName().replace(".json", ""), score);
        }

        try {
            String foreword = String.format("%25s %10s%b%n", "isEmptyCertAcceptable", " ", isEmptyCertAcceptable) +
                    String.format("%25s %10s%d%n", "cost time", " ", costTime);
            exportMatchScoreToTxtFile(foreword, matchScores, Paths.get(outputDir, outputFilename + ".txt").toString(), 100);
            saveProbeResponsesToJsonFile(targetProbingResult, Paths.get(outputDir, outputFilename + ".json").toString());
            System.out.printf("%25s: %25s: %15s%s...%n", "Saving", connector.getTargetHostname(), " ", "Finished");
        } catch (Exception e) {
            System.err.printf("%25s: %25s: %15s%s%n", "Saving", connector.getTargetHostname(), " ", "Error");
        }
        System.out.printf("%25s: %25d%n", "cost time", costTime);

        post();
    }

    private LinkedHashMap<String, ArrayList<String>> probing() throws IOException {
        LinkedHashMap<String, ArrayList<String>> results = new LinkedHashMap<>();
        StatelessProbe statelessProbe = new StatelessProbe(new StatelessParser());
        List<StatefulProbe> statefulProbes = loadProbes(probeFilepath);

        List<String> probeResponses = new ArrayList<>();
        int probeNum = 0;
        for (String response : statelessProbe.probe(connector, isEmptyCertAcceptable)) {
            if (Objects.equals(response, "") && !probeResponses.isEmpty()) {
                results.put(statelessProbeRequests.get(probeNum), (ArrayList<String>) probeResponses);
                probeResponses = new ArrayList<>();
                probeNum++;
                continue;
            }
            probeResponses.add(response);
        }

        System.out.printf("%25s: %25s: %15s%s...%n", "Probing", connector.getTargetHostname(), " ", statelessProbe.getID());
        interval();

        for (StatefulProbe statefulProbe : statefulProbes) {
            System.out.printf("%25s: %25s: %15s%s...%n", "Probing", connector.getTargetHostname(), " ", statefulProbe.getID());
            probeResponses = queryCache(List.of(statefulProbe.getRequests()));
            if (probeResponses == null) {
                probeResponses = statefulProbe.probe(connector, isEmptyCertAcceptable);
                if (!probeResponses.isEmpty() && probeResponses.get(probeResponses.size() - 1).contains(SYMBOL_CONNECTION_CLOSED)) {
                    updateCache(List.of(statefulProbe.getRequests()), probeResponses);
                }
                interval();
            }
            results.put(statefulProbe.getID(), (ArrayList<String>) probeResponses);
        }

        return results;
    }

    private int responseMatch(LinkedHashMap<String, ArrayList<String>> probingResult, JSONObject database) {
        int score = 0;
        for (Map.Entry<String, ArrayList<String>> entry : probingResult.entrySet()) {
            String probeID = entry.getKey();
            ArrayList<String> oneProbeResponses = new ArrayList<>();
            JSONArray oneProbeResponses_ = database.getJSONArray(probeID);
            for (int i = 0; i < oneProbeResponses_.size(); i++) {
                oneProbeResponses.add(oneProbeResponses_.getString(i));
            }
            if (statelessProbeRequests.contains(probeID)) {
                oneProbeResponses.retainAll(entry.getValue());
                score = score + oneProbeResponses.size();
            } else {
                if (!isEmptyCertAcceptable) {
                    String[] requests = probeID.split(",");
                    int length = Math.min(entry.getValue().size(), oneProbeResponses.size());
                    int certNum = 0;
                    for (int i = 0; i < length; i++) {
                        if (Objects.equals(requests[i], "CERT")) {
                            oneProbeResponses.remove(i - certNum);
                            certNum++;
                        }
                    }
                }
                if (entry.getValue().equals(oneProbeResponses)) {
                    score++;
                }
            }
        }
        return score;
    }

    private void interval() {
        if (interval > 0) {
            try {
                TimeUnit.MILLISECONDS.sleep(interval);
            } catch (InterruptedException e) {
                System.err.printf("%25s: %25s: %15s%s%n", "Interval", connector.getTargetHostname(), " ", "Failed");
            }
        }
    }

    private void updateCache(List<String> requests, List<String> responses) {
        if (!isEmptyCertAcceptable) {
            requests = requests.stream().filter(x -> !x.contains(CERT)).collect(Collectors.toList());
        }
        requests = requests.subList(0, responses.size());
        String key = String.join(",", requests);
        List<String> readableRequests = requests.stream().map(x -> ABBREVIATION.inverse().get(x)).collect(Collectors.toList());
        if (!probingCache.containsKey(key)) {
            System.out.printf("%25s: %25s: %15s%s...%n", "Add cache", connector.getTargetHostname(), " ", String.join(",", readableRequests));
        } else {
            System.out.printf("%25s: %25s: %15s%s...%n", "Update cache", connector.getTargetHostname(), " ", String.join(",", readableRequests));
        }
        probingCache.put(key, responses);
    }

    private List<String> queryCache(List<String> requests) {
        if (!isEmptyCertAcceptable) {
            requests = requests.stream().filter(x -> !x.contains(CERT)).collect(Collectors.toList());
        }
        String key = String.join(",", requests);
        for (String k : probingCache.keySet()) {
            if (key.startsWith(k)) {
                List<String> readableRequests = Arrays.stream(k.split(",")).map(x -> ABBREVIATION.inverse().get(x)).collect(Collectors.toList());
                System.out.printf("%25s: %25s: %15s%s...%n", "Hit cache", connector.getTargetHostname(), " ", String.join(",", readableRequests));
                return probingCache.get(k);
            }
        }
        return null;
    }

    private boolean isHelloSuccessful() {
        try {
            String[] testRequests = new String[]{CH, CERT, CKE, CCS, FIN, ALERT};
            StatefulProbe testProbe = new StatefulProbe(testRequests, new StatefulParser(), "CH,CERT,CKE,CCS,FIN,ALERT");
            List<String> probeResponses = testProbe.probe(connector, true);

            if (probeResponses.size() <= 1) {
                System.err.printf("%25s: %25s: %15s%s%n", "HelloNegotiation", connector.getTargetHostname(), " ", "Failed");
                return false;
            } else if (probeResponses.get(1).contains(SYMBOL_CONNECTION_CLOSED)) {
                isEmptyCertAcceptable = false;
                System.out.printf("%25s: %25s: %15s%s...%n", "HelloNegotiation", connector.getTargetHostname(), " ", "Successful");
                System.out.printf("%25s: %25s: %15s%s...%n", "EmptyCertificate", connector.getTargetHostname(), " ", "Unacceptable");
            } else {
                isEmptyCertAcceptable = true;
                System.out.printf("%25s: %25s: %15s%s...%n", "HelloNegotiation", connector.getTargetHostname(), " ", "Successful");
                System.out.printf("%25s: %25s: %15s%s...%n", "EmptyCertificate", connector.getTargetHostname(), " ", "Acceptable");
            }
            return true;
        } catch (Exception e) {
            System.err.printf("%25s: %25s: %15s%s%n", "HelloNegotiation", connector.getTargetHostname(), " ", "Error");
            return false;
        }
    }

    private List<StatefulProbe> loadProbes(String probeFileName) throws IOException {
        List<StatefulProbe> statefulProbes = new ArrayList<>();
        List<String> probes = FileUtils.readLines(new File(probeFileName));

        probes.sort((o1, o2) -> Integer.compare(o2.split(" -> ").length, o1.split(" -> ").length));

        for (String probe : probes) {
            statefulProbes.add(new StatefulProbe(
                    Arrays.stream(probe.split(" -> ")).map(x -> ABBREVIATION.get(x)).toArray(String[]::new),
                    new StatefulParser(),
                    String.join(",", probe.split(" -> "))
            ));
        }
        return statefulProbes;
    }

    private JSONObject readResponseMatchFile(File file) {
        String fileContent = null;
        try {
            fileContent = FileUtils.readFileToString(file);
        } catch (IOException e) {
            System.err.printf("%25s: %25s: %15s%s%n", "Reading", file.getPath(), " ", "Error");
        }
        return JSON.parseObject(fileContent);
    }

    private void post() {
        probingCache.clear();
    }

    private void exportMatchScoreToTxtFile(String foreword, LinkedHashMap<String, Integer> scores, String filepath, int displayNum) throws IOException {
        assert displayNum > 0;

        File f = new File(filepath);
        if (!f.createNewFile()) {
            System.err.printf("%25s: %25s: %15s%s%n", "Creating", filepath, " ", "File already exists");
        }
        FileOutputStream fileOutputStream = new FileOutputStream(f);
        OutputStreamWriter writer = new OutputStreamWriter(fileOutputStream);

        if (foreword != null && !foreword.equals("")) {
            writer.write(foreword);
        }

        List<Map.Entry<String, Integer>> descScores = Utils.sortMapByValue(scores, false);
        for (Map.Entry<String, Integer> score : descScores) {
            writer.write(String.format("%25s %10s%d%n", score.getKey(), " ", score.getValue()));
            displayNum--;
            if (displayNum == 0)
                break;
        }
        writer.close();
    }

    private void saveProbeResponsesToJsonFile(LinkedHashMap<String, ArrayList<String>> probingResult, String filepath) {
//        LinkedHashMap<String, ArrayList<String>> f = new LinkedHashMap<>();
//        LinkedHashMap<String, ArrayList<String>> stateless = new LinkedHashMap<>();
//        LinkedHashMap<String, ArrayList<String>> stateful = new LinkedHashMap<>();
//
//        for (Map.Entry<String, ArrayList<String>> entry : probingResult.entrySet()) {
//            if (statelessProbeRequests.contains(entry.getKey())) {
//                stateless.put(entry.getKey(), entry.getValue());
//            } else {
//                stateful.put(entry.getKey(), entry.getValue());
//            }
//        }
//        List<Map.Entry<String, ArrayList<String>>> orderedStateless = Utils.sortMapByKey(stateless, false);
//        List<Map.Entry<String, ArrayList<String>>> orderedStateful = Utils.sortMapByKey(stateful, true);
//        for (Map.Entry<String, ArrayList<String>> entry : orderedStateless) {
//            f.put(entry.getKey(), entry.getValue());
//        }
//        for (Map.Entry<String, ArrayList<String>> entry : orderedStateful) {
//            f.put(entry.getKey(), entry.getValue());
//        }

        ObjectMapper mapper = new ObjectMapper();
        try {
            String json = mapper.writeValueAsString(probingResult);
            Utils.writeFile(filepath, Utils.formatJSON(json));
        } catch (JsonProcessingException e) {
            System.err.printf("%25s: %25s: %15s%s%n", "Writing", filepath, " ", "Error");
        }

    }


    public void setOutputFilename(String outputFilename) {
        this.outputFilename = outputFilename;
    }

    public String getOutputFilename() {
        return outputFilename;
    }

    public String getOutputDir() {
        return outputDir;
    }

    public void setInterval(int interval) {
        this.interval = interval;
    }

    public void scanMultiTargets(String outputDir, int scoreThreshold) {
        File identifiedTlsDirectory = new File(outputDir);

        if (neo4j == null) {
            initialiseNeo4jDriver(n4jUrl, username, password);
        }

        for (File identifiedTlsFile : Objects.requireNonNull(identifiedTlsDirectory.listFiles())) {
            if (identifiedTlsFile.isFile() && identifiedTlsFile.getName().endsWith(".txt")) {
                scanOneTarget(identifiedTlsFile.getPath(), scoreThreshold);
                System.out.println("--------------------------------------------------------------------");
            }
        }
    }

    public void scanOneTarget(String identifiedTlsFilepath, int scoreThreshold) {
        System.out.println("--------------------------------------------------------------------");

        if (neo4j == null) {
            initialiseNeo4jDriver(n4jUrl, username, password);
        }

        File identifiedTlsFile = new File(identifiedTlsFilepath);

        List<String> identifiedTlsWithHighestScore = new ArrayList<>();
        List<String> potentialCves = new ArrayList<>();

        try {
            String[] identifiedTls = FileUtils.readFileToString(identifiedTlsFile).split("\n");
            if (identifiedTls.length < 2) {
                System.err.printf("%25s: %25s: %15s%s%n", "Scanning", identifiedTlsFile.getName(), " ", "The file contains less than two lines");
                return;
            }

            String[] theFirstTlsInfo = identifiedTls[2].trim().split("\\s");
            int highestScore = Integer.parseInt(theFirstTlsInfo[theFirstTlsInfo.length - 1]);
            if (highestScore < scoreThreshold) {
                System.err.printf("%25s: %25s: %15s%s%n", "Scanning", identifiedTlsFile.getName(), " ", "Prediction may not be credible ( the highest score < " + scoreThreshold + " )");
                return;
            }

            for (int i = 2; i < identifiedTls.length; i++) {
                String[] tlsInfo = identifiedTls[i].trim().split("\\s");
                Matcher versionMatcher = Pattern.compile("(.*?)-").matcher(tlsInfo[0]);
                String tlsVersion = versionMatcher.replaceAll(r -> r.group(1).toUpperCase() + "-");
                int tlsScore = Integer.parseInt(tlsInfo[tlsInfo.length - 1]);
                if (tlsScore < highestScore) {
                    break;
                } else {
                    System.out.printf("%25s: %25s: %15s%s...%n", "Scanning", identifiedTlsFile.getName(), " ", tlsVersion);
                    List<String> CVE = queryNeo4jDatabase(
                            neo4j,
                            "MATCH (a)-->(b:CVE) WHERE a.version = $var RETURN b AS ret",
                            tlsVersion,
                            "id"
                    );
                    identifiedTlsWithHighestScore.add(tlsVersion);
                    potentialCves.addAll(CVE);
                }
            }

            List<String> securityReport = new ArrayList<>();
            securityReport.add(String.format(
                    "%25s %10s%2d %10s%s",
                    identifiedTlsFile.getName().replace(".txt", ""),
                    " ", identifiedTlsWithHighestScore.size(),
                    " ", String.join(", ", identifiedTlsWithHighestScore))
            );
            securityReport.add(String.format("%60s", "-".repeat(60)));
            for (Map.Entry<String, Long> cve : potentialCves
                    .stream()
                    .collect(Collectors.groupingBy(k -> k, Collectors.counting()))
                    .entrySet()
                    .stream()
                    .sorted(Collections.reverseOrder(Map.Entry.comparingByValue()))
                    .collect(Collectors.toList())) {
                String frequencyOfCVE;
                if (cve.getValue() != identifiedTlsWithHighestScore.size()) {
                    List<String> tlsAffectedByCve = queryNeo4jDatabase(
                            neo4j,
                            "MATCH (a:CVE)<--(b) WHERE a.id = $var RETURN b AS ret",
                            cve.getKey(),
                            "version"
                    );
                    tlsAffectedByCve.retainAll(identifiedTlsWithHighestScore);
                    frequencyOfCVE = String.join(", ", tlsAffectedByCve);
                } else {
                    frequencyOfCVE = "all";
                }
                securityReport.add(String.format(
                        "%25s %10s%2d %10s%s",
                        cve.getKey(),
                        " ", cve.getValue(),
                        " ", frequencyOfCVE
                ));
            }
            FileUtils.writeLines(new File(identifiedTlsFilepath.replace(".txt", ".security.txt")), securityReport);
        } catch (IOException e) {
            System.err.printf("%25s: %25s: %15s%s%n", "Scanning", identifiedTlsFilepath, " ", "Error");
        }
    }

    public ArrayList<String> queryNeo4jDatabase(Driver driver, final String cypher, final String parameter, String field) {
        ArrayList<String> results = new ArrayList<>();
        try (Session session = driver.session()) {
            session.writeTransaction(tx -> {
                Result records = tx.run(cypher, parameters("var", parameter));
                while (records.hasNext()) {
                    Record record = records.next();
                    Node node = record.get("ret").asNode();
                    results.add(node.get(field).toString().replaceAll("\"", ""));
                }
                return null;
            });
        }
        return results;
    }

    private void isDirExists(String dirPath) {
        File directory = new File(dirPath);
        if (directory.exists() && directory.isDirectory()) {
//            System.out.printf("%25s: %25s: %15s%s...%n", "Creating", dirPath, " ", "Directory already exists");
        } else {
            boolean isSuccessful = directory.mkdirs();
            if (isSuccessful) {
                System.out.printf("%25s: %25s: %15s%s...%n", "Creating", dirPath, " ", "Successful");
            } else {
                System.err.printf("%25s: %25s: %15s%s...%n", "Creating", dirPath, " ", "Failed");
            }
        }
    }
}

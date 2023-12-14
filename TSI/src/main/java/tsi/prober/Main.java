package tsi.prober;

import org.apache.commons.cli.*;

import java.nio.file.Paths;
import java.util.Objects;

public class Main {

    public static void main(String[] args) throws ParseException {
        /* Definition Stage */
        Options options = new Options();

        Option help = Option.builder()
                .option("h")
                .longOpt("help")
                .hasArg(false)
                .desc("print the help message")
                .build();
        options.addOption(help);

        Option vulScan = Option.builder()
                .longOpt("cve")
                .hasArg(false)
                .desc("scan potential known vulnerabilities")
                .build();
        options.addOption(vulScan);

        /* --------------------------------------------------------------------------------------------------------- */

        Option config = Option.builder()
                .longOpt("config")
                .argName("file")
                .hasArg()
                .desc("use a customized configuration file")
                .build();
        options.addOption(config);

        Option probe = Option.builder()
                .longOpt("probe")
                .argName("file")
                .hasArg()
                .desc("use a customized probe file")
                .build();
        options.addOption(probe);

        Option responseMatchDatabase = Option.builder()
                .longOpt("responseMatchDB")
                .argName("directory")
                .hasArg()
                .desc("use a customized TLS behaviors database ")
                .build();
        options.addOption(responseMatchDatabase);

        /* --------------------------------------------------------------------------------------------------------- */

        Option outputFilename = Option.builder()
                .longOpt("out")
                .argName("filename")
                .hasArg()
                .desc("specify the name of the output file")
                .build();
        options.addOption(outputFilename);

        Option interval = Option.builder()
                .longOpt("interval")
                .argName("time")
                .hasArg()
                .desc("set the time interval between probes")
                .build();
        options.addOption(interval);

        /* --------------------------------------------------------------------------------------------------------- */

        Option domains = Option.builder()
                .longOpt("domainFile")
                .argName("file")
                .hasArg()
                .desc("if you want to identify domains in batch, write domains in a csv file")
                .build();
        options.addOption(domains);

        Option address = Option.builder()
                .longOpt("address")
                .argName("ip")
                .hasArg()
                .desc("(required) the IP address of the target to be identified")
                .build();
        options.addOption(address);

        Option port = Option.builder()
                .longOpt("port")
                .argName("port")
                .hasArg()
                .desc("(required) the port of the target to be identified")
                .build();
        options.addOption(port);

        /* --------------------------------------------------------------------------------------------------------- */

        /* Parsing Stage */
        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);

        /* --------------------------------------------------------------------------------------------------------- */

        /* Interrogation Stage */
        String configFilepath;
        String probeFilepath;
        String responseMatchDatabaseDir;

        if (cmd.hasOption("config")) {
            configFilepath = cmd.getOptionValue("config");
        } else {
//            configFilepath = Objects.requireNonNull(Main.class.getClassLoader().getResource("/config.properties")).getPath();
            configFilepath = "./input/config.properties";
        }

        if (cmd.hasOption("probe")) {
            probeFilepath = cmd.getOptionValue("probe");
        } else {
//            probeFilepath = Objects.requireNonNull(Main.class.getClassLoader().getResource("/Probes.txt")).getPath();
            probeFilepath = "./input/Probes.txt";
        }

        if (cmd.hasOption("responseMatchDB")) {
            responseMatchDatabaseDir = cmd.getOptionValue("responseMatchDB");
        } else {
//            responseMatchDatabaseDir = Objects.requireNonNull(Main.class.getClassLoader().getResource("/ResponseMatchDatabase")).getPath();
            responseMatchDatabaseDir = "./input/ResponseMatchDatabase";
        }

        Prober prober = new Prober(configFilepath, probeFilepath, responseMatchDatabaseDir);

        /* --------------------------------------------------------------------------------------------------------- */

        if (cmd.hasOption("interval")) {
            prober.setInterval(Integer.parseInt(cmd.getOptionValue("interval")));
        }

        /* --------------------------------------------------------------------------------------------------------- */

        int scoreThreshold = 50;

        if (cmd.hasOption("domainFile")) {
            prober.identifyMultiTargets(cmd.getOptionValue("domainFile"));

            if (cmd.hasOption("cve")) {
                prober.scanMultiTargets(prober.getOutputDir(), scoreThreshold);
            }
        } else if (cmd.hasOption("address") && cmd.hasOption("port")) {
            if (cmd.hasOption("out")) {
                prober.setOutputFilename(cmd.getOptionValue("out"));
            } else {
                prober.setOutputFilename(cmd.getOptionValue("address"));
            }

            prober.identifyOneTarget(cmd.getOptionValue("address"), Integer.parseInt(cmd.getOptionValue("port")));

            if (cmd.hasOption("cve")) {
                prober.scanOneTarget(
                        Paths.get(prober.getOutputDir(), prober.getOutputFilename() + ".txt").toString(),
                        scoreThreshold
                );
            }
        } else if (cmd.hasOption("h")) {
            // automatically generate the help statement
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("TSI-Prober --address=[IP] --port=[PORT] ...", options);
        } else {
            System.err.println("Illegal usage. \nPlease refer to the help information by --help or -h option.");
        }
    }
}
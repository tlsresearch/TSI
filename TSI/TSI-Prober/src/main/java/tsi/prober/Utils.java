package tsi.prober;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Utils {
    private static String CHARS = "0123456789ABCDEF";

    public static String bytesToHex(byte[] bytes) {
        StringBuffer hex = new StringBuffer();

        for (int i = 0; i < bytes.length; i++) {
            int n1 = (bytes[i] >> 4) & 0x0F;
            hex.append(CHARS.charAt(n1));
            int n2 = bytes[i] & 0x0F;
            hex.append(CHARS.charAt(n2));
        }

        return hex.toString();
    }

    public static byte[] hexToBytes(String hex) {
        //TODO Check if string contains only hex characters
        if (hex.length() % 2 != 0) hex = "0" + hex;

        byte[] bytes = new byte[hex.length() / 2];

        for (int i = 0; i < hex.length(); i = i + 2) {
            bytes[i / 2] = Integer.decode("0x" + hex.substring(i, i + 2)).byteValue();
        }

        return bytes;
    }

    /**
     * This function takes in a list of elements and returns a map that shows the frequency of each element in the list.
     * It uses Java 8 streams to group the elements by their values and count the number of occurrences.
     * If the input list is empty, an empty map is returned.
     *
     * @param falcons the list of elements
     * @param <T> the type of the elements
     * @return a map representing the frequency of each element, where the key is the element itself and the value is the frequency
     */
    public static <T> Map<T, Long> frequencyOfElementsInList(List<T> falcons) {
        if (falcons.isEmpty()) {
            return new HashMap<>();
        }
        return falcons.stream().collect(Collectors.groupingBy(k -> k, Collectors.counting()));
    }


    /**
     * Sorts the given map by its values and returns the sorted map entries as a list.
     *
     * @param map the map to be sorted
     * @param asc a boolean value indicating whether the sorting order is ascending or descending
     * @return a list of sorted map entries
     */
    public static <K, V extends Comparable<? super V>> List<Map.Entry<K, V>> sortMapByValue(Map<K, V> map, boolean asc) {
        Stream<? extends Map.Entry<K, V>> stream = null;
        if (asc) {
            stream = map.entrySet().stream().sorted(Map.Entry.comparingByValue());
        } else {
            stream = map.entrySet().stream().sorted(Collections.reverseOrder(Map.Entry.comparingByValue()));
        }

        return stream.collect(Collectors.toList());
    }


    /**
     * Sorts the given map by its keys and returns the sorted map entries as a list.
     *
     * @param map the map to be sorted
     * @param asc whether to sort in ascending order or not
     * @param <K> the type of the keys
     * @param <V> the type of the values
     * @return the sorted list of entries
     */
    public static <K extends Comparable<? super K>, V> List<Map.Entry<K, V>> sortMapByKey(Map<K, V> map, boolean asc) {
        Stream<? extends Map.Entry<K, V>> stream = null;
        if (asc) {
            stream = map.entrySet().stream().sorted(Map.Entry.comparingByKey());
        } else {
            stream = map.entrySet().stream().sorted(Collections.reverseOrder(Map.Entry.comparingByKey()));
        }

        return stream.collect(Collectors.toList());
    }


    /**
     * Formats the JSON data and saves it to a file.
     *
     * @param jsonData   the JSON data to be output
     * @param filePath   the path of the output file
     * @return true if the file creation was successful, false otherwise
     */
    public static boolean createJsonFile(Object jsonData, String filePath) {
        String content = (String) jsonData;

        // Indicates whether file creation is successful
        boolean flag = true;

        // Creates the JSON file
        try {
            File file = new File(filePath);
            if (!file.getParentFile().exists()) { // If the parent directory does not exist, create the directory
                file.getParentFile().mkdirs();
            }
            if (file.exists()) { // If the file already exists, delete the old file
                file.delete();
            }
            file.createNewFile();

            // Writes the formatted string into the file
            Writer write = new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8);
            write.write(content);
            write.flush();
            write.close();
        } catch (Exception e) {
            flag = false;
            e.printStackTrace();
        }
        return flag;
    }


    /**
     * Formats a JSON string by adding line breaks and tabs for better readability.
     *
     * @param jsonStr the JSON string to be formatted
     * @return the formatted JSON string
     */
    public static String formatJSON(String jsonStr) {
        int level = 0;
        StringBuilder jsonForMatStr = new StringBuilder();
        for (int i = 0; i < jsonStr.length(); i++) {
            char c = jsonStr.charAt(i);
            if (level > 0 && '\n' == jsonForMatStr.charAt(jsonForMatStr.length() - 1)) {
                jsonForMatStr.append(getLevelStr(level));
            }
            switch (c) {
                case '{':
                case '[':
                    jsonForMatStr.append(c).append("\n");
                    level++;
                    break;
                case ',':
                    char d = jsonStr.charAt(i - 1);
                    if (d == '"' || d == ']') {
                        jsonForMatStr.append(c).append("\n");
                    } else {
                        jsonForMatStr.append(c);
                    }
                    break;
                case '}':
                case ']':
                    jsonForMatStr.append("\n");
                    level--;
                    jsonForMatStr.append(getLevelStr(level));
                    jsonForMatStr.append(c);
                    break;
                default:
                    jsonForMatStr.append(c);
                    break;
            }
        }
        return jsonForMatStr.toString();
    }


    private static String getLevelStr(int level) {
        return "\t".repeat(Math.max(0, level));
    }

    /**
     * Write the content of a string to a local file.
     *
     * @param filepath The path where the file will be saved.
     * @param content The content to be saved in the file.
     */
    public static void writeFile(String filepath, String content) {
        FileWriter fileWriter;
        try {
            fileWriter = new FileWriter(filepath);
            fileWriter.write(content);
            fileWriter.flush();
            fileWriter.close();
        } catch (IOException e) {
            System.out.println("An exception occurs when writing to the file: " + filepath);
            throw new RuntimeException(e);
        }
    }


    /**
     * Check if the given address and port are reachable.
     *
     * @param addr the target address
     * @param port the port number
     * @param timeOutMillis the timeout in milliseconds
     * @return true if the address and port are reachable, false otherwise
     */
    public static boolean isReachable(String addr, int port, int timeOutMillis) {
        // Any Open port on target machine
        // port = 22 - ssh, 80 or 443 - web server, 25 - mail server etc.
        try (Socket soc = new Socket()) {
            soc.connect(new InetSocketAddress(addr, port), timeOutMillis);
            return true;
        } catch (IOException ex) {
            return false;
        }
    }

}

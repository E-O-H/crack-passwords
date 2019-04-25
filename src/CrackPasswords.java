/*
* Name: Chenyang Tang
* Description: The program tries to crack hashed passwords given their hashes and salts. Hash function is SHA-512 with results truncated to 256bits. 
* The program can try various techniques by combining dictionary words, prefix/sufix words with guess strings, 
* substitute for uppercase letters and other symbols, as well as brute-force on specified character set. 
* Many other techniques are further detailed in the code.
* (symbol substitutions used: a -> @, b -> 6, e -> 3, g -> 9, i -> !, l -> 1, l -> |, l -> 7, o -> 0, s -> $, s-> 5, 
* t -> +, v -> ^, v -> <, v -> >, w -> vv, w -> VV, w -> uu, w -> UU, x -> +)
*/

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Queue;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import javafx.util.Pair;


/**
 * The class to crack passwords with SHA-512 based on a given dictionary
 * 
 * @author Chenyang Tang
 */
public class CrackPasswords {
  
  private static final String passwordPath = "files\\pswd.txt";
  private static final String dictionaryPath = "files\\simpledictionary.txt";
  
  private static final int minGuessYear = 1900;           // minimum for years as combination units
  private static final int maxGuessYear = 2020;           // maximum for years as combination units
  private static final int maxGuessNumberShort = 100;     // maximum for numbers as combination units
  private static final int maxGuessNumberLong = 1000000;  // maximum for numbers as stand-alone password
  private static final int maxComboLength = 2;            // maximum number of combination units
  private static final int maxRepeatLength = 6;           // maximum repeating times
  private static final int maxBruteLength = 4;            // maximum brute-force length

  private static final char[] characterSet = {            // Brute-force character set
      ' ', '\t', '\b', '\r', 
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 
      'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 
      'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 
      'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 
      '`', '~', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', 
      '[', ']', '{', '}', '\\', '|', ';', ':', '\'', '"', ',', '.', '<', '>', '/', '?'
  };
  private static final List<Pair<Character, String>> substituteRules = Arrays.asList( // character substitution rules
      new Pair<>('a', "A"), new Pair<>('b', "B"), new Pair<>('c', "C"), new Pair<>('d', "D"), new Pair<>('e', "E"), 
      new Pair<>('f', "F"), new Pair<>('g', "G"), new Pair<>('h', "H"), new Pair<>('i', "I"), new Pair<>('j', "J"), 
      new Pair<>('k', "K"), new Pair<>('l', "L"), new Pair<>('m', "M"), new Pair<>('n', "N"), new Pair<>('o', "O"), 
      new Pair<>('p', "P"), new Pair<>('q', "Q"), new Pair<>('r', "R"), new Pair<>('s', "S"), new Pair<>('t', "T"), 
      new Pair<>('u', "U"), new Pair<>('v', "V"), new Pair<>('w', "W"), new Pair<>('x', "X"), new Pair<>('y', "Y"), 
      new Pair<>('z', "Z"), new Pair<>('a', "@"), new Pair<>('b', "6"), new Pair<>('e', "3"), new Pair<>('g', "9"), 
      new Pair<>('i', "!"), new Pair<>('l', "1"), new Pair<>('l', "|"), new Pair<>('o', "0"), new Pair<>('s', "$"), 
      new Pair<>('s', "5"), new Pair<>('t', "+"), new Pair<>('v', "^"), new Pair<>('v', "<"), new Pair<>('v', ">"),
      new Pair<>('w', "vv"), new Pair<>('w', "VV"), new Pair<>('w', "uu"), new Pair<>('w', "UU"), new Pair<>('x', "+")
    );
  private static final String[] guessList = { // predefined guessing strings
                                              // More sequenced/patterned ones will be extended at runtime
      "",
      "password", "pwd", "pass word",
      "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
      "january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december",
      "qw", "qwe", "qwer", "qwert", "qwerty", "qaz", "wsx", "qazwsx",
      "as", "asd", "asdf", "asdfg", "asdfgh",
      "zx", "zxc", "zxcv", "zxcvb", "zxcvbn",
      "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg", "abcdefgh", "aabb", "aabbcc", 
      "xy", "xyz", "xxyy", "xxyyzz", "xyzxyz",
      "12", "123", "1234", "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
      "21", "321", "4321", "54321", "654321", "7654321", "87654321", "987654321", "0987654321",
      "10", "210", "3210", "43210", "543210", "6543210", "76543210", "876543210", "9876543210",
      "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13", "14", "15",
      "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31",
      "!@", "!@#", "!@#$", "!@#$%", "!@#$%^", "!@#$%^&", "!@#$%^&*", "!@#$%^&*(", "!@#$%^&*()"
  }; 
  
  private static List<char[]> usernames = new ArrayList<char[]>();
  private static List<String> saltsBase64 = new ArrayList<String>();
  private static List<byte[]> salts = new ArrayList<byte[]>();
  private static List<Integer> iterations = new ArrayList<Integer>();
  private static List<String> hashBase64 = new ArrayList<String>();
  private static List<byte[]> hash = new ArrayList<byte[]>();
  private static List<char[]> dictionary = new ArrayList<char[]>();  
  
  private static List<String> passwords;
  
  /**
   * Entry point
   * 
   * @param args args not used
   */
  public static void main(String[] args) {
    // Read and parse files
    readFiles(passwordPath, dictionaryPath);
    // Decode Base64
    Base64.Decoder decoder = Base64.getDecoder();
    for (int i = 0; i < saltsBase64.size(); ++i) {
      salts.add(decoder.decode(saltsBase64.get(i)));
      hash.add(decoder.decode(hashBase64.get(i)));
    }
    
    // Calculate key length
    int keyLength = hash.get(0).length * 8; // number of bytes * 8 bits

    Integer count = 0; // number of successful cracks
    boolean[] cracked = new boolean[usernames.size()];
    passwords = new ArrayList<String>(Collections.nCopies(usernames.size(), "********"));
                                                                   // cracked passwords; "********" denotes uncracked
    
    dictionary.addAll(usernames);
    // Add capitalized words and first letter capitalized words to the dictionary
    int nWords = dictionary.size();
    for (int i = 0; i < nWords; ++i) {
      String str = String.valueOf(dictionary.get(i));
      dictionary.add(str.toUpperCase().toCharArray());
      dictionary.add((str.substring(0, 1).toUpperCase() + str.substring(1)).toCharArray());
    }
    
    // Create list of guessing-strings
    List<char[]> strList = new ArrayList<char[]>();
    // add manual guess list
    for (String str : guessList) {
      strList.add(str.toCharArray());
    }
    // add repeats of character set
    for (char c : characterSet) {
      for (int i = 0; i <= maxRepeatLength; ++i) {
        strList.add((new String(new char[i]).replace('\0', c)).toCharArray());
      }
    }
    // add more numbers
    for (int i = 32; i <= maxGuessNumberShort; ++i) {
      strList.add(String.valueOf(i).toCharArray());
    }
    // add recent years
    for (int i = minGuessYear; i <= maxGuessYear; ++i) {
      strList.add(String.valueOf(i).toCharArray());
    }
    
    // FIRST PASS: substitute for uppercase letters and symbols on every possible combination of positions (extended dictionary)
    System.out.printf("FIRST PASS: substitute for uppercase letters and other symbols \n");
    System.out.printf("            on every possible combination of positions (extended dictionary)\n");
    // create a new dictionary with modded words
    System.out.printf("Preparing... ");
    List<char[]> dictionaryMod = new ArrayList<char[]>();
    for (char[] word : dictionary) {
      // substitute character on every possible combination of positions in a word
      Queue<char[]> queue = new ArrayDeque<char[]>();
      queue.offer(word);
      for (int j = 0; j < word.length; ++j) {
        char[] tmp;
        List<char[]> mods = new ArrayList<char[]>();
        while ((tmp = queue.poll()) != null) {
          mods.add(tmp);                                                  // not substitute this character
          mods.addAll(substituteChar(tmp, tmp.length - word.length + j)); // substitute this character
        }
        queue.addAll(mods);
      }
      dictionaryMod.addAll(queue);
    }
    System.out.printf("Done\n");
    
    for (int i = 0; i < usernames.size(); ++i) {
      System.out.printf("Attempting user %d... ", i);
      if (cracked[i] == true) {
        System.out.printf("Cracked  (\"%s\")\n", passwords.get(i));
        continue;
      }
      for (int j = 0; j < dictionaryMod.size(); ++j) {
        if (Arrays.equals(hashPassword(dictionaryMod.get(j),salts.get(i),iterations.get(i), keyLength), hash.get(i))) {
          passwords.set(i, String.valueOf(dictionaryMod.get(j)));
          cracked[i] = true;
          ++count;
          System.out.printf("Success! (\"%s\")", passwords.get(i));
          break;
        }
      }
      System.out.printf("\n");
    }
    if(testFinish(count, usernames.size())) return;
    
    // SECOND PASS: Combinations of original dictionary words and character set and guessing-strings (predefined)
    System.out.printf("SECOND PASS: Combinations of original dictionary words "
                     + "and character set and guessing-strings (predefined)\n");
    // create a list of combinations
    System.out.printf("Preparing... ");
    // Each element in comboList is a combination of strings in unitList
    List<char[]> comboList = new ArrayList<char[]>();
    List<char[]> unitList = new ArrayList<char[]>();
    unitList.addAll(dictionary);
    for (char c : characterSet) {
      unitList.add(String.valueOf(c).toCharArray());
    }
    for (String s : guessList) {
      unitList.add(s.toCharArray());
    }
    for (int i = 1; i <= maxComboLength; ++i) {
      comboList.addAll(generateAllCombo(unitList, i));
    }
    System.out.printf("Done\n");
    
    for (int i = 0; i < usernames.size(); ++i) {
      System.out.printf("Attempting user %d... ", i);
      if (cracked[i] == true) {
        System.out.printf("Cracked  (\"%s\")\n", passwords.get(i));
        continue;
      }
      for (int j = 0; j < comboList.size(); ++j) {
        if (Arrays.equals(hashPassword(comboList.get(j),salts.get(i),iterations.get(i), keyLength), hash.get(i))) {
          passwords.set(i, String.valueOf(comboList.get(j)));
          cracked[i] = true;
          ++count;
          System.out.printf("Success! (\"%s\")", passwords.get(i));
          break;
        }
      }
      System.out.printf("\n");
    }
    if(testFinish(count, usernames.size())) return;
    
    // THIRD PASS: prefix/suffix guessing-strings (extended) to username 
    System.out.printf("THIRD PASS: prefix/suffix guessing-strings (extended) to username\n");
    System.out.printf("Preparing... ");
    System.out.printf("Done\n");
    
    for (int i = 0; i < usernames.size(); ++i) {
      System.out.printf("Attempting user %d... ", i);
      if (cracked[i] == true) {
        System.out.printf("Cracked  (\"%s\")\n", passwords.get(i));
        continue;
      }
      testPrefixSuffix(usernames, strList, cracked, count, keyLength, i);
      System.out.printf("\n");
    }
    if(testFinish(count, usernames.size())) return;

    // FOURTH PASS: prefix/suffix guessing-strings (extended) to original dictionary 
    System.out.printf("FOURTH PASS: prefix/suffix guessing-strings (extended) to original dictionary \n");
    System.out.printf("Preparing... ");
    System.out.printf("Done\n");
    
    for (int i = 0; i < usernames.size(); ++i) {
      System.out.printf("Attempting user %d... ", i);
      if (cracked[i] == true) {
        System.out.printf("Cracked  (\"%s\")\n", passwords.get(i));
        continue;
      }
      testPrefixSuffix(dictionary, strList, cracked, count, keyLength, i);
      System.out.printf("\n");
    }
    if(testFinish(count, usernames.size())) return;
 
    
/* Uncomment codes below for more time-consuming tests.
    // FIFTH PASS: Repeat of an extended dictionary word, guessing-string or character set
    //             (including outer repeat (repeat of whole word) and inner repeat (repeat of characters inside a word)
    System.out.printf("FIFTH PASS: Repeat of extended dictionary words and character set \n            "
                    + "(including outer repeat (repeat of whole word) and inner repeat (repeat of characters inside a word)");
    System.out.printf("Preparing... ");
    List<char[]> allStringList = new ArrayList<char[]>();
    allStringList.addAll(dictionaryMod);
    allStringList.addAll(strList);
    for (char c : characterSet) {
      allStringList.add(String.valueOf(c).toCharArray());
    }
    System.out.printf("Done\n");
    
    // Outer repeats
    System.out.printf("(Outer repeats)\n");
    for (int i = 0; i < usernames.size(); ++i) {
      System.out.printf("Attempting user %d... ", i);
      if (cracked[i] == true) {
        System.out.printf("Cracked  (\"%s\")\n", passwords.get(i));
        continue;
      }
      for (int r = 1; r <= maxRepeatLength; ++r) {
        for (int j = 0; j < allStringList.size(); ++j) {
          String repeated = new String(new char[r]).replace("\0", String.valueOf(allStringList.get(j)));
          if (Arrays.equals(hashPassword(repeated.toCharArray() ,salts.get(i), iterations.get(i), keyLength), hash.get(i))) {
            passwords.set(i, repeated);
            cracked[i] = true;
            ++count;
            System.out.printf("Success! (\"%s\")", passwords.get(i));
            break;
          }
        }
      }
      System.out.printf("\n");
    }
    if(testFinish(count, usernames.size())) return;
    
    // Inner repeats
    System.out.printf("(Inner repeats)\n");
    for (int i = 0; i < usernames.size(); ++i) {
      System.out.printf("Attempting user %d... ", i);
      if (cracked[i] == true) {
        System.out.printf("Cracked  (\"%s\")\n", passwords.get(i));
        continue;
      }
      for (int j = 0; j < allStringList.size(); ++j) {
        char[] repeated = new char[allStringList.get(j).length * maxRepeatLength];
        for (int k = 0; k < repeated.length; ++k) {
          repeated[k] = allStringList.get(j)[k / maxRepeatLength];
        }
        if (Arrays.equals(hashPassword(repeated, salts.get(i), iterations.get(i), keyLength), hash.get(i))) {
          passwords.set(i, String.valueOf(repeated));
          cracked[i] = true;
          ++count;
          System.out.printf("Success! (\"%s\")", passwords.get(i));
          break;
        }
      }
      System.out.printf("\n");
    }
    if(testFinish(count, usernames.size())) return;
    
    // SIXTH PASS: Sandwich structures with original dictionary words on both ends
    System.out.printf("SIXTH PASS: Sandwich structures\n");
    System.out.printf("Preparing... ");
    System.out.printf("Done\n");
    // Single character in the middle
    System.out.printf("(Single character in the middle)\n");
    for (int i = 0; i < usernames.size(); ++i) {
      System.out.printf("Attempting user %d... ", i);
      if (cracked[i] == true) {
        System.out.printf("Cracked  (\"%s\")\n", passwords.get(i));
        continue;
      }
      for (char[] a : dictionary) {
        for (char[] b : dictionary) {
          for (char c : characterSet) {
            if (Arrays.equals(hashPassword((String.valueOf(a) + String.valueOf(c) + String.valueOf(b)).toCharArray(), salts.get(i), iterations.get(i), keyLength), hash.get(i))) {
              passwords.set(i, String.valueOf(a) + String.valueOf(c) + String.valueOf(b));
              cracked[i] = true;
              ++count;
              System.out.printf("Success! (\"%s\")", passwords.get(i));
              break;
            }
          }
        }
      }
      System.out.printf("\n");
    }
    if(testFinish(count, usernames.size())) return;
    
    // Guessing-string (predefined) in the middle
    System.out.printf("(Guessing-string in the middle)\n");
    for (int i = 0; i < usernames.size(); ++i) {
      System.out.printf("Attempting user %d... ", i);
      if (cracked[i] == true) {
        System.out.printf("Cracked  (\"%s\")\n", passwords.get(i));
        continue;
      }
      for (char[] a : dictionary) {
        for (char[] b : dictionary) {
          for (String c : guessList) {
            if (Arrays.equals(hashPassword((String.valueOf(a) + String.valueOf(c) + String.valueOf(b)).toCharArray(), salts.get(i), iterations.get(i), keyLength), hash.get(i))) {
              passwords.set(i, String.valueOf(a) + String.valueOf(c) + String.valueOf(b));
              cracked[i] = true;
              ++count;
              System.out.printf("Success! (\"%s\")", passwords.get(i));
              break;
            }
          }
        }
      }
      System.out.printf("\n");
    }
    if(testFinish(count, usernames.size())) return;
    
    
    // SEVENTH PASS: Brute-force number sequence
    System.out.printf("SEVENTH PASS: Brute-force number sequence \n");
    
    for (int i = 0; i < usernames.size(); ++i) {
      System.out.printf("Attempting user %d... ", i);
      if (cracked[i] == true) {
        System.out.printf("Cracked  (\"%s\")\n", passwords.get(i));
        continue;
      }
      for (int j = 0 - maxGuessNumberLong; j <= maxGuessNumberLong; ++j) {
        if (Arrays.equals(hashPassword(String.valueOf(j).toCharArray(),salts.get(i),iterations.get(i), keyLength), hash.get(i))) {
          passwords.set(i, String.valueOf(String.valueOf(j)));
          cracked[i] = true;
          ++count;
          System.out.printf("Success! (\"%s\")", passwords.get(i));
          break;
        }
      }
      for (int j = 0; j < maxGuessNumberLong; ++j) {
        if (Arrays.equals(hashPassword(("0" + String.valueOf(j)).toCharArray(),salts.get(i),iterations.get(i), keyLength), hash.get(i))) {
          passwords.set(i, String.valueOf("0" + String.valueOf(j)));
          cracked[i] = true;
          ++count;
          System.out.printf("Success! (\"%s\")", passwords.get(i));
          break;
        }
      }
      System.out.printf("\n");
    }
    if(testFinish(count, usernames.size())) return;

    // EIGHTH PASS: prefix/suffix guessing-strings (extended) to extended dictionary 
    System.out.printf("EIGHTH PASS: prefix/suffix guessing-strings (extended) to extended dictionary \n");
    System.out.printf("Preparing... ");
    System.out.printf("Done\n");
    
    for (int i = 0; i < usernames.size(); ++i) {
      System.out.printf("Attempting user %d... ", i);
      if (cracked[i] == true) {
        System.out.printf("Cracked  (\"%s\")\n", passwords.get(i));
        continue;
      }
      testPrefixSuffix(dictionaryMod, strList, cracked, count, keyLength, i);
      System.out.printf("\n");
    }
    if(testFinish(count, usernames.size())) return;

    // NINTH PASS: prefix/suffix guessing-strings to combined words 
    System.out.printf("NINTH PASS: prefix/suffix guessing-strings to combined words \n");
    System.out.printf("Preparing... ");
    System.out.printf("Done\n");
    
    for (int i = 0; i < usernames.size(); ++i) {
      System.out.printf("Attempting user %d... ", i);
      if (cracked[i] == true) {
        System.out.printf("Cracked  (\"%s\")\n", passwords.get(i));
        continue;
      }
      testPrefixSuffix(comboList, strList, cracked, count, keyLength, i);
      System.out.printf("\n");
    }
    if(testFinish(count, usernames.size())) return;
*/

/*
    // TENTH PASS: Combination of extended dictionary words and character set
    System.out.printf("TENTH PASS: Combination of extended dictionary words and character set\n");
    // create a list of combinations
    System.out.printf("Preparing... ");
    // Each element in comboList is a combination of strings in unitList
    comboList = new ArrayList<char[]>();
    unitList = new ArrayList<char[]>();
    unitList.addAll(dictionaryMod);
    for (char c : characterSet) {
      unitList.add(String.valueOf(c).toCharArray());
    }
    for (int i = 1; i <= maxComboLength; ++i) {
      comboList.addAll(generateAllCombo(unitList, i));
    }
    System.out.printf("Done\n");
    
    for (int i = 0; i < usernames.size(); ++i) {
      System.out.printf("Attempting user %d... ", i);
      if (cracked[i] == true) {
        System.out.printf("Cracked  (\"%s\")\n", passwords.get(i));
        continue;
      }
      for (int j = 0; j < comboList.size(); ++j) {
        if (Arrays.equals(hashPassword(comboList.get(j),salts.get(i),iterations.get(i), keyLength), hash.get(i))) {
          passwords.set(i, String.valueOf(comboList.get(j)));
          cracked[i] = true;
          ++count;
          System.out.printf("Success! (\"%s\")", passwords.get(i));
          break;
        }
      }
      System.out.printf("\n");
    }
    if(testFinish(count, usernames.size())) return;
*/

/*
  // FINAL PASS: Brute-force whole character set without dictionary
     System.out.printf("FINAL PASS: Brute force whole character set without dictionary\n");
     // create a list of combinations
     System.out.printf("Preparing... ");
     // Each element in bruteList is a combination of characters in charList
     List<char[]> bruteList = new ArrayList<char[]>();
     List<char[]> charList = new ArrayList<char[]>();
     for (char c : characterSet) {
       charList.add(String.valueOf(c).toCharArray());
     }
     for (int i = 1; i <= maxBruteLength; ++i) {
       bruteList.addAll(generateAllCombo(charList, i));
     }
     System.out.printf("Done\n");
     
     for (int i = 0; i < usernames.size(); ++i) {
       System.out.printf("Attempting user %d... ", i);
       if (cracked[i] == true) {
         System.out.printf("Cracked  (\"%s\")\n", passwords.get(i));
         continue;
       }
       for (int j = 0; j < bruteList.size(); ++j) {
         if (Arrays.equals(hashPassword(bruteList.get(j),salts.get(i),iterations.get(i), keyLength), hash.get(i))) {
           passwords.set(i, String.valueOf(bruteList.get(j)));
           cracked[i] = true;
           ++count;
           System.out.printf("Success! (\"%s\")", passwords.get(i));
           break;
         }
       }
       System.out.printf("\n");
     }
     if(testFinish(count, usernames.size())) return;
*/
    
    printResults();
  }
  
  
  /**
   * Modify a word by substituting one character on a specified position.
   * possible modifications: 
   * lowercase to uppercase, a -> @, b -> 6, e -> 3, g -> 9, i -> !, l -> 1, l -> |, l -> 7, o -> 0, s -> $, s-> 5, 
   * t -> +, v -> ^, v -> <, v -> >, w -> vv, w -> VV, w -> uu, w -> UU, x -> +
   * 
   * @param word The word to be modded
   * @param pos The position of the char to be substituted
   * @return A list of all possible modded words
   */
  static List<char[]> substituteChar(char[] word, int pos) {
    List<char[]> ret = new ArrayList<char[]>();
    for (Pair<Character, String> e : substituteRules) {
      if (e.getKey().equals(word[pos])) {
        ret.add((String.valueOf(word).substring(0, pos) + e.getValue() + String.valueOf(word).substring(pos + 1)).toCharArray());
      }
    }
    return ret;
  }
  
  /**
   * Test for Prefix/suffix with a guessing-string
   * @param strList string list
   * @param cracked cracked list
   * @param count number cracked
   * @param dictionary dictionary
   * @param keyLength length of hash
   */
  private static void testPrefixSuffix(List<char[]> dictionary, List<char[]> strList, boolean[] cracked, 
                                       Integer count , int keyLength, int i) {
    // test for guessing-string alone
    for (int k = 0; k < strList.size(); ++k) {
      if (Arrays.equals(hashPassword(strList.get(k),salts.get(i),iterations.get(i), keyLength), hash.get(i))) {
        passwords.set(i, String.valueOf(strList.get(k)));
        cracked[i] = true;
        ++count;
        System.out.printf("Success! (\"%s\")", passwords.get(i));
        return;
      }
    }
    // test for dictionary + guessing-string
    // without space
    for (int j = 0; j < dictionary.size(); ++j) {
      for (int k = 0; k < strList.size(); ++k) {
        if (Arrays.equals(hashPassword((String.valueOf(dictionary.get(j)) + String.valueOf(strList.get(k))).toCharArray(), 
                                       salts.get(i),iterations.get(i), keyLength), hash.get(i))) {
          passwords.set(i, String.valueOf(dictionary.get(j)) + String.valueOf(strList.get(k)));
          cracked[i] = true;
          ++count;
          System.out.printf("Success! (\"%s\")", passwords.get(i));
          return;
        }
      }
    }
    // with space
    for (int j = 0; j < dictionary.size(); ++j) {
      for (int k = 0; k < strList.size(); ++k) {
        if (Arrays.equals(hashPassword((String.valueOf(dictionary.get(j)) + " " + String.valueOf(strList.get(k))).toCharArray(), 
                                       salts.get(i),iterations.get(i), keyLength), hash.get(i))) {
          passwords.set(i, String.valueOf(dictionary.get(j)) + " " + String.valueOf(strList.get(k)));
          cracked[i] = true;
          ++count;
          System.out.printf("Success! (\"%s\")", passwords.get(i));
          return;
        }
      }
    }
    // test for guessing-string + dictionary
    // without space
    for (int j = 0; j < dictionary.size(); ++j) {
      for (int k = 0; k < strList.size(); ++k) {
        if (Arrays.equals(hashPassword((String.valueOf(strList.get(k)) + String.valueOf(dictionary.get(j))).toCharArray(), 
                                       salts.get(i),iterations.get(i), keyLength), hash.get(i))) {
          passwords.set(i, String.valueOf(strList.get(k)) + String.valueOf(dictionary.get(j)));
          cracked[i] = true;
          ++count;
          System.out.printf("Success! (\"%s\")", passwords.get(i));
          return;
        }
      }
    }
    // with space
    for (int j = 0; j < dictionary.size(); ++j) {
      for (int k = 0; k < strList.size(); ++k) {
        if (Arrays.equals(hashPassword((String.valueOf(strList.get(k)) + " " + String.valueOf(dictionary.get(j))).toCharArray(), 
                                       salts.get(i),iterations.get(i), keyLength), hash.get(i))) {
          passwords.set(i, String.valueOf(strList.get(k)) + " " + String.valueOf(dictionary.get(j)));
          cracked[i] = true;
          ++count;
          System.out.printf("Success! (\"%s\")", passwords.get(i));
          return;
        }
      }
    }
    // test for guessing-string + dictionary + guessing-string
    // without space
    for (int j = 0; j < dictionary.size(); ++j) {
      for (int k = 0; k < strList.size(); ++k) {
        if (Arrays.equals(hashPassword((
             String.valueOf(strList.get(k)) + String.valueOf(dictionary.get(j)) + String.valueOf(strList.get(k))).toCharArray(), 
             salts.get(i),iterations.get(i), keyLength), hash.get(i))
           ) {
          passwords.set(i, String.valueOf(strList.get(k)) + String.valueOf(dictionary.get(j)) + String.valueOf(strList.get(k)));
          cracked[i] = true;
          ++count;
          System.out.printf("Success! (\"%s\")", passwords.get(i));
          return;
        }
      }
    }
    // with space
    for (int j = 0; j < dictionary.size(); ++j) {
      for (int k = 0; k < strList.size(); ++k) {
        if (Arrays.equals(hashPassword((
             String.valueOf(strList.get(k)) + " " + String.valueOf(dictionary.get(j)) + " " + String.valueOf(strList.get(k))).toCharArray(), 
             salts.get(i),iterations.get(i), keyLength), hash.get(i))
           ) {
          passwords.set(i, String.valueOf(strList.get(k)) + " " + String.valueOf(dictionary.get(j)) + " " + String.valueOf(strList.get(k)));
          cracked[i] = true;
          ++count;
          System.out.printf("Success! (\"%s\")", passwords.get(i));
          return;
        }
      }
    }
  }
  
  /**
   * Read files
   */
  private static void readFiles(String passwordPath, String dictionaryPath) {  
    try {
      // Read password file
      File file = new File(passwordPath); 
      BufferedReader br = new BufferedReader(new FileReader(file)); 
      br.readLine(); // Discard the first line
      String line; 
      while ((line = br.readLine()) != null) {
        String[] tokens = line.split("[ \t]*:[ \t]*");
        usernames.add(tokens[0].toCharArray());
        saltsBase64.add(tokens[1]);
        iterations.add(Integer.parseInt(tokens[2]));
        hashBase64.add(tokens[3]);
      }
      br.close();
      
      // Read dictionary file
      file = new File(dictionaryPath);
      br = new BufferedReader(new FileReader(file));
      while ((line = br.readLine()) != null) {
        dictionary.add(line.trim().toCharArray()); // Note the dictionary files has some unwanted blank spaces on some lines!!!
      }
      br.close();
    } catch (Exception e) {
        System.out.println(e);
    }
  }
  
  /**
   * Test if finished
   */
  private static boolean testFinish(int count, int total) {
    if (count == total) {
      printResults();
      return true;
    }
    return false;
  }
  
  /**
   * Display results
   */
  private static void printResults() {
    System.out.printf("========================\n");
    //System.out.printf("%-15s%-20s\n", "username", "password");
    System.out.printf("Results:\n");
    System.out.printf("========================\n");
    for (int i = 0; i < usernames.size(); ++i) {
      //System.out.printf("%-15s%s\n", String.valueOf(usernames.get(i)), passwords.get(i));
      System.out.printf("%s::%s\n", String.valueOf(usernames.get(i)), passwords.get(i));
    }
  }
  
  /** 
   * Generate all possible combination of concatenating k strings (without space). 
   */
  static List<char[]> generateAllCombo(List<char[]> set, int k) { 
     List<char[]> ret = new ArrayList<char[]>();
     generateAllComboRec(set, "", k, ret); 
     return ret;
  } 

  private static void generateAllComboRec(List<char[]> set, String prefix, int k, List<char[]> ret) { 
     // Base case: k is 0, 
     // output prefix 
     if (k == 0) { 
         ret.add(prefix.toCharArray());
         return; 
     } 
   
     // One by one concatenate all strings from set and recursively call the function
     for (int i = 0; i < set.size(); ++i) { 
         // Next part added 
         String newPrefix = prefix + String.valueOf(set.get(i));  
         // Recursion for k - 1
         generateAllComboRec(set, newPrefix, k - 1, ret);  
     } 
  }
  
  /** 
   * Generate all possible combination of concatenating k strings (with space). 
   */
  static List<char[]> generateAllComboWithSpace(List<char[]> set, int k) { 
     List<char[]> ret = new ArrayList<char[]>();
     generateAllComboWithSpaceRec(set, "", k, ret); 
     return ret;
  } 

  private static void generateAllComboWithSpaceRec(List<char[]> set, String prefix, int k, List<char[]> ret) { 
     // Base case: k is 0, 
     // output prefix 
     if (k == 0) { 
         ret.add(prefix.toCharArray());
         return; 
     } 
   
     // One by one concatenate all strings from set and recursively call the function
     if (prefix.equals("") == false ) prefix += " ";
     for (int i = 0; i < set.size(); ++i) { 
         // Next part added 
         String newPrefix = prefix + String.valueOf(set.get(i));  
         // Recursion for k - 1
         generateAllComboWithSpaceRec(set, newPrefix, k - 1, ret);  
     } 
  }
  
  /**
   * Hash Function (SHA-512)
   */
  private static byte[] hashPassword(final char[] password, final byte[] salt, final int iterations, final int keyLength) {
    try {
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey key = skf.generateSecret(spec);
        byte[] res = key.getEncoded();
        return res;
    } catch(NoSuchAlgorithmException | InvalidKeySpecException e) {
        throw new RuntimeException(e);
    }
  }
}

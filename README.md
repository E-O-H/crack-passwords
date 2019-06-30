# crack-passwords
The program tries to crack hashed passwords given their hashes and salts. Hash function is SHA-512 with results truncated to 256bits. 

The program tries various techniques by combining dictionary words, prefix/sufix words with guess strings, 
substitute for uppercase letters and other symbols, as well as brute-force on specified character set. 
Many other techniques are further detailed in the code.

(symbol substitutions used: a -> @, b -> 6, e -> 3, g -> 9, i -> !, l -> 1, l -> |, l -> 7, o -> 0, s -> $, s-> 5, 
t -> +, v -> ^, v -> <, v -> >, w -> vv, w -> VV, w -> uu, w -> UU, x -> +)

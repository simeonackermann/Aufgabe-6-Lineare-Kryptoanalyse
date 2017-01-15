package aufgabe;

import java.util.Arrays;
import java.util.Random;

public class crypt {
	
	// Anzahl der known pairs
	int numKnown = 65536;
	// S-Box Substitution
	Integer[] sBox = {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7};
	// Transpositions Tabelle der DES Verschlüsselung
	int[] transTable = {1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16};
	// Approximationstabelle
	int[][] approxTable = new int[16][16];
	// Anzahl der Runden zur Verschlüsselung (kann nicht dynamisch geändert werden)
	int numRounds = 4;
	// known plaintexts
	int[] knownP = new int[numKnown];
	// known ciphertext
	int[] knownC = new int[numKnown];	
	// Ergebnisse der Häufigkeit der Teilschlüssel
	double[] subkeyBias = new double[16*16];
	
	void main(String[] args) {
		System.out.println("Known Plaintext Paare erstellen...");
	    fillKnowns();
	    System.out.printf("  Klartext (erste 16): %s ...\n", Arrays.toString(Arrays.copyOfRange(knownP, 0, 16)));
	    System.out.printf("  Ciphertext (erste 16): %s ...\n", Arrays.toString(Arrays.copyOfRange(knownC, 0, 16)));
	    System.out.printf("Insgesamt %d Known Pairs erstellt.\n", knownP.length);
	    
	    System.out.println("\nApproximationstabelle erstellen...");
	 	findApprox();
	 	showApprox();
		
	    System.out.println("\nTeilschlüssel finden...");
	    findPartKeys();
	    System.out.println("Index und Werte:");
	    showPartTable();	    
	    
	    //Schlüsselbits der letzten Runde - Aus Array den Eintrag auslesen mit höchster Abweichung von 1/2
	    int indexHighestValue = getIndexOfHighestValue();	
	    //Eintrag in Hexadezimalzahl wandeln
	    int key1 = Math.floorDiv(indexHighestValue, 16) % 16;
	    int key2 = indexHighestValue % 16;
	    
	    System.out.println("\nIndex des höchsten Wertes: " + indexHighestValue);
	    System.out.println("Teilschlüssel [5-8]:\t" + key1);
	    System.out.println("Teilschlüssel [13-16]:\t " + key2);
	}
	
	//Schlüsselbits der letzten Runde auslesen
	int getIndexOfHighestValue() {
		double max = -1;
		int index = 0;
		for (int i = 0; i < subkeyBias.length; i++) {
			if (subkeyBias[i] > max) {
				max = subkeyBias[i];
				index = i;
			}
		}
		return index;
	}
	
	//Ausgabe der Tabelle zum Matsui Algorithmus
	void showPartTable() {
		for (int i = 0; i < subkeyBias.length / 4; i++) {
			System.out.printf("%d\t%f\t %d\t%f\t %d\t%f\t %d\t%f\n", i, subkeyBias[i], i+64, subkeyBias[i+64], i+128, subkeyBias[i+128], i+192, subkeyBias[i+192]);
		}
	}
	
	//Lineare Gleichung nach Matsui aufstellen und Treffer in subkeyBias zählen
	void findPartKeys() {
		//Zwei Schleifen bis 16 für alle möglichen Schlüsselbits K5,5 ... K5,8 ; K5,13 ... K5,16
		for (int i = 0; i < 16; i++) {
			System.out.printf(" %d...", i);
			for (int j = 0; j < 16; j++) {				
				for (int a = 0; a < numKnown; a++) {
					String plaint = toBinary(knownP[a], 16);
					String ciphert = toBinary(knownC[a], 16);
					
					String c1 = ciphert.substring(4, 8);
					String c2 = ciphert.substring(12, 16);
					
					//XOR mit Rundenschlüssel 5
					int v1 = i ^ toDecimal(c1);
					int v2 = j ^ toDecimal(c2);
					
					//Invers Lookup der Sbox 4,2 bzw. 4,4
					Integer u1 = Arrays.asList(sBox).indexOf(v1);
					Integer u2 = Arrays.asList(sBox).indexOf(v2);
					String u1Str = toBinary(u1, 4);
					String u2Str = toBinary(u2, 4);					  
					
					//Gleichung siehe Heys S. 15
					//U4,6 xor U4,8 xor U4,14 xor U4,16 xor P5 xor P7 xor P8 = 0 
					if ((	toDecimal(u1Str.substring(1, 2)) ^ 
							toDecimal(u1Str.substring(3, 4)) ^ 
							toDecimal(u2Str.substring(1, 2)) ^ 
							toDecimal(u2Str.substring(3, 4)) ^ 
							toDecimal(plaint.substring(4, 5)) ^ 
							toDecimal(plaint.substring(6, 7)) ^ 
							toDecimal(plaint.substring(7, 8))) == 0
					) {
						subkeyBias[(i*16) + j]++;
					}
				}				
				//Prozentuale Abweichung von 1/2
				subkeyBias[(i*16) + j] = Math.abs(subkeyBias[(i*16) + j] - numKnown/2) / numKnown;
			}
		}
		System.out.printf("\n");
	}
	
	/*
	 * Maske auf input anwenden (a1 * Y1 ^ a2 * Y2) siehe Heys S.11
	 */
	int applyMask(int input, int mask) {
		String inputBin = toBinary(input, 4);
		Integer in1 = toDecimal(inputBin.substring(0, 1));
		Integer in2 = toDecimal(inputBin.substring(1, 2));
		Integer in3 = toDecimal(inputBin.substring(2, 3));
		Integer in4 = toDecimal(inputBin.substring(3, 4));
		
		String maskBin = toBinary(mask, 4);
		Integer m1 = toDecimal(maskBin.substring(0, 1));
		Integer m2 = toDecimal(maskBin.substring(1, 2));
		Integer m3 = toDecimal(maskBin.substring(2, 3));
		Integer m4 = toDecimal(maskBin.substring(3, 4));
		
		return in1 * m1 ^ in2 * m2 ^ in3 * m3 ^ in4 * m4 ;
	}
	
	/*
	 * Approximationstabelle erstellen
	 */
	void findApprox() {
		// output mask b, Spalten durchlaufen
		for(int b = 1; b < 16; b++) {
			// input mask a, Zeilen durchlaufen
	        for(int a = 1; a < 16; a++) {
	        	// input, jede Zelle für 16 Fälle testen 
	            for(int e = 0; e < 16; e++) {
	            	// Wenn a & X == b & Y approxTable inkrementieren
	            	if (applyMask(e, a) == applyMask(sBox[e], b)) {
	                    approxTable[a][b]++;
	                }	            	
	            }
	            // Jeden Eintrag minus 8 für Normalisierung
	            approxTable[a][b] -= 8;
	        }
		}
	}
	
	/*
	 * Approximationstabelle ausgeben
	 */
	void showApprox() {
	    System.out.println("Approximationstabelle: (input mask \\ output mask)");
		System.out.printf("\t0\t1\t2\t3\t4\t5\t6\t7\t8\t9\t10\t11\t12\t13\t14\t15\n");
	    for(int c = 0; c < 16; c++) {
	    	System.out.printf("%d\t", c);
	        for(int d = 0; d < 16; d++) {
	        	System.out.printf("%d\t", approxTable[c][d]);
	        }
	        System.out.printf("\n");
	    }
	}
	
	/*
	 * Known Pairs erstellen
	 */
	void fillKnowns() {
		Random rand = new Random(); 
	    int[] roundKeys = new int[numRounds+1];
	    for (int j = 0; j <= numRounds; j++) {
	    	roundKeys[j] = Math.abs(rand.nextInt()) % numKnown;
        	System.out.printf("  Rundenschlüssel %d: %s (%s)\n", j+1, roundKeys[j], toBinary(roundKeys[j], 16));
	    }
	    
	    for(int i = 0; i < numKnown; i++) {
	    	// known plaintext erstellen, mit 2^16 mögl. Werten
	        knownP[i] = Math.abs(rand.nextInt()) % numKnown;
	        
	        // known ciphertext erstellen, dafür x runden durchlaufen
	        knownC[i] = knownP[i];
	        for (int j = 1; j <= numRounds; j++) {
	        	if (j == numRounds) {
	        		knownC[i] = lastRoundFunc(knownC[i], roundKeys[j-1], roundKeys[j]);
	        	} else {
	        		knownC[i] = roundFunc(knownC[i], roundKeys[j-1]);
	        	}
			}
	    }
	}
	
	/*
	 * Rundenfunktion für DES
	 * @input Plaintext
	 * @subkey Rundenschlüssel
	 */
	int roundFunc(int input, int subkey) {
		input = input ^ subkey;
		return transposition(substitution(input));
	}
	
	/*
	 * Letzte Runde für DES (ohne Transposition)
	 * @input Plaintext
	 * @subkey Rundenschlüssel
	 */
	int lastRoundFunc(int input, int subkey1, int subkey2) {
		input = input ^ subkey1;
		input = substitution(input);
		input = input ^ subkey2;
		return input;
	}
	
	/*
	 * Substitution mit S-Box für  DES
	 * @input Plaintext
	 * @subkey Rundenschlüssel
	 */
	int substitution(int input) {
		String bin = toBinary(input, 16);
		String bin1 = bin.substring(0, 4);
		Integer bin1Int = sBox[toDecimal(bin1)];
		
		String bin2 = bin.substring(4, 8);
		Integer bin2Int = sBox[toDecimal(bin2)];
		
		String bin3 = bin.substring(8, 12);
		Integer bin3Int = sBox[toDecimal(bin3)];
		
		String bin4 = bin.substring(12, 16);
		Integer bin4Int = sBox[toDecimal(bin4)];
		
		String result = toBinary(bin1Int, 4) + toBinary(bin2Int, 4) + toBinary(bin3Int, 4) + toBinary(bin4Int, 4);
		return toDecimal(result);
	}
	
	/*
	 * Transposition mit Transpositionstabelle für DES
	 * @input Eingabezahl
	 */
	int transposition(int input) {
		String inputStr = toBinary(input, 16);
		String result = "";
		for (int i = 1; i <= transTable.length; i++) {
			result += inputStr.charAt(transTable[i - 1] - 1);
		}		
		return toDecimal(result);
	}
	
	/*
	 * Dualzahl fester Länge aus Dezimalzahl erstellen
	 * @input Dezimalzahl
	 * @length Länge
	 */
	String toBinary(int input, int length) {
		String binarized = Integer.toBinaryString(input);
		int len = binarized.length();
		String zeros = "";
		for (int i = 1; i <= length; i++) {
			zeros += "0";
		}
		if (len < length) {
		  binarized = zeros.substring(0, length-len).concat(binarized);
		} else {
		  binarized = binarized.substring(len - length);
		}
		return binarized;
	}
	
	/*
	 * Dezimalzahl (Integer) aus String erzeugen
	 * @input Eingabe-String
	 */
	Integer toDecimal(String input) {
		return Integer.parseInt(input, 2);
	}
}

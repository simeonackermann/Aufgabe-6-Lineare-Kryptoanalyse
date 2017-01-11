package aufgabe;

import java.util.Arrays;
import java.util.Random;

public class crypt {
	
	// substitution
	int[] sBox = {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7};
	// reverse substitution für entschlüsselung
	int[] revSbox = {14, 5, 6, 10, 3, 15, 7, 9, 11, 0, 4, 1, 2, 8, 13, 12};
	// 
	int[] xValues = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	int[] yValues = {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7};
	// transpositions tabelle
	int[] transTable = {1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16};
	// approximationstabelle
	int[][] approxTable = new int[16][16];
	// anzahl der paare
	int numKnown = 65536; // = 2^16
	// known plaintexts
	int[] knownP = new int[numKnown];
	// known ciphertext
	int[] knownC = new int[numKnown];
	
	void main(String[] args) {
		// approximationstabelle berechnen
		findApprox();
		// approximtionstabelle anzeigen
		showApprox();
		System.out.println("Approx Tabelle" + Arrays.deepToString(approxTable));
		
		int inputApprox = 11;
	    int outputApprox = 11;
	    fillKnowns();
	    System.out.println("Known P: " + Arrays.toString(Arrays.copyOfRange(knownP, 0, 16)));
	    System.out.println("Known C: " + Arrays.toString(Arrays.copyOfRange(knownC, 0, 16)));
	    
	    return;
		
	    /*int[] keyScore = new int[16];
	    int sofar1 = 0;
	    
	    System.out.printf("Linear Attack:  Using Linear Approximation = %d -> %d\n", inputApprox, outputApprox);
	    
	    for(int c = 0; c < 16; c++) {
	        for(int d = 0; d < numKnown; d++) {
	            sofar1++;
	            int midRound = roundFunc(knownP[d], c);         //Find Xi by guessing at K1
	            
	            if ((applyMask(midRound, inputApprox) == applyMask(knownC[d], outputApprox))) {
	                keyScore[c]++;
	            } else {
	                keyScore[c]--;
	            }   
	        }
	    }
	    
	    int maxScore = 0;
	    for(int c = 0; c < 16; c++) {
	        int score = keyScore[c] * keyScore[c];
	        if (score > maxScore) maxScore = score;
	    }
	    
	    int[] goodKeys = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
	    
	    int d = 0;	    
	    for(int c = 0; c < 16; c++) {
	        if ((keyScore[c] * keyScore[c]) == maxScore) {
	            goodKeys[d] = c;
	            System.out.printf("Linear Attack:  Candidate for K1 = %d\n", goodKeys[d]);
	            d++;
	        }
	    }
	    
	    for(d = 0; d < 16; d++)    
	    {
	        if (goodKeys[d] != -1) {
	                int k1test = roundFunc(knownP[0], goodKeys[d]) ^ revSbox[knownC[0]];

	                int bad = 0;
	                for(int e = 0;e < numKnown; e++) {
	                    sofar1 += 2;
	                    int testOut = roundFunc(roundFunc(knownP[e], goodKeys[d]), k1test);
	                    if (testOut != knownC[e]) {
	                        bad = 1;
	                    }
	                }
	                if (bad == 0) {
	                    System.out.printf("Linear Attack:  Found Keys! K1 = %d, K2 = %d\n", goodKeys[d], k1test);
	                    System.out.printf("Linear Attack:  Computations Until Key Found = %d\n", sofar1);
	                }
	 
	        }    
	    }
	    
	    System.out.printf("Linear Attack:  Computations Total = %d\n\n", sofar1);
	    */
	}
	
	int applyMask(int value, int mask)
	{
	    int interValue = value & mask; //Ersatz für Multiplikation a*X bzw. b*Y
	    int total = 0;
	    
	    while(interValue > 0)
	    {
	        int temp = interValue % 2;    
	        interValue /= 2;
	        
	        if (temp == 1) {
	            total = total ^ 1;
	        }
	    } 
	    return total;   
	}
	
	void findApprox() {
		// output mask b, spalten durchlaufen
		for(int b = 1; b < 16; b++) {
			// input mask a, zeilen durchlaufen
	        for(int a = 1; a < 16; a++) {
	        	// input, jede zelle für 16 fälle testen 
	            for(int e = 0; e < 16; e++) {
	            	// wenn a & X1-4 == b & Y1-4 approx tabelle inkrementieren
	            	if (applyMask(e, a) == applyMask(yValues[e], b)) {
	                    approxTable[a][b]++;
	                }
	            }
	        }
		}
		// jeden eintrag minus 8 für normalisierung
		for(int b = 1; b < 16; b++) {
			for(int a = 1; a < 16; a++) {
				approxTable[a][b] -= 8;
			}
		}
	}
	
	void showApprox() {
	    System.out.println("Gute Lineare Approximationen:");
	    for(int c = 1; c < 16; c++) {
	        for(int d = 1; d < 16; d++) {
	            if (Math.abs(approxTable[c][d]) >= 6) {
	                System.out.printf("  %d : %d -> %d\n", approxTable[c][d], c, d);
	            	//System.out.println(approxTable[c][d] + " ");
	            }
	        }
	    }
	}
	
	void fillKnowns() {
		Random rand = new Random(); 
	    int subKey1 = Math.abs(rand.nextInt()) % numKnown;
	    int subKey2 = Math.abs(rand.nextInt()) % numKnown;
	    
	    System.out.printf("Data Generator:  K1 = %d, K2 = %d\n", subKey1, subKey2);
	    
	    for(int i = 0; i < numKnown; i++) {
	    	// known plaintext erstellen, mit 2^16 mögl. werten
	        knownP[i] = Math.abs(rand.nextInt()) % numKnown;
	    
	        //knownC[i] = roundFunc(roundFunc(knownP[i], subKey1), subKey2); 
	        knownC[i] = roundFunc(knownP[i], subKey2);
	    }    
	    
	    System.out.printf("Data Generator:  Generated %d Known Pairs\n\n", numKnown);
	}
	
	// input = known plaintext, subkey = rundenschlüssel
	int roundFunc(int input, int subkey)
	{
		//System.out.println("input ^ subkey]: " + (input ^ subkey));
	    //return sBox[input ^ subkey];
		String bin = toBinary(input, 16);
		String bin1 = bin.substring(0, 3);
		Integer bin1Int = sBox[toInteger(bin1)];
		
		String bin2 = bin.substring(4, 7);
		Integer bin2Int = sBox[toInteger(bin2)];
		
		String bin3 = bin.substring(8, 11);
		Integer bin3Int = sBox[toInteger(bin3)];
		
		String bin4 = bin.substring(12, 15);
		Integer bin4Int = sBox[toInteger(bin4)];
		
		String bin1234 = toBinary(bin1Int, 4) + toBinary(bin2Int, 4) + toBinary(bin3Int, 4) + toBinary(bin4Int, 4);
		//String result = bin1234.substring(0, 0) + bin1234.substring(4, 4);
		String result = "";
		//bin1234.charAt(index)
		for (int i = 1; i <= transTable.length; i++) {
			result += bin1234.charAt(transTable[i - 1] - 1);
		}
		
		return toInteger(result);
	}
	
	String toBinary(int input, int length) {
		//return Integer.toBinaryString(0x10000 | input).substring(1);
		String binarized = Integer.toBinaryString(input);
		int len = binarized.length();
		//String sixteenZeroes = "00000000000000000";
		String zeros = "";
		for (int i = 1; i <= length; i++) {
			zeros += "0";
		}
		if (len < length)
		  binarized = zeros.substring(0, length-len).concat(binarized);
		else
		  binarized = binarized.substring(len - length);
		return binarized;
	}
	
	Integer toInteger(String input) {
		return Integer.parseInt(input, 2);
	}
	
	
	

}

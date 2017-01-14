<b>Lineare Kryptoanalyse nach Matsui</b></br>
Implementierung in Java

<strong> 1  Allgemein</strong>

Ziel des Programms ist die Lineare Kryptoanalyse einer DES Verschlüsselung in 4 Runden mit Schlüssellänge 64 Bit.

Die Implementierung fundiert auf dem Paper von Howard M. Heys "A Tutorial on Linear and Differential Cryptanalysis", 
welches hier zu finden ist: https://www.engr.mun.ca/~howard/PAPERS/ldc_tutorial.pdf sowie auf der Vorlesung von Prof. Dr. Geser.
Der Code selbst ist zum Teil inspiriert von der C Implementierung von Jon King, hier zu finden: http://www.theamazingking.com/crypto-linear.php
</br>
Das Programm hat keinen Input, d.h. es kann nicht als Angriff auf fremde Verschlüsselungen verwendet werden. </br>
Stattdessen werden zufällige plaintext/ciphertext Paare generiert.
</br>
Das Projekt ist im Rahmen der Vorlesung Kryptologie an der HTWK Leipzig im WS 2016/17 entstanden.</br>
Umgesetzt von Simeon Ackermann & Tim Menapace.

<strong> 2  Anwendung </strong>

Als User reicht es die main.java Funktion zu kompilieren und auszuführen.</br>
Die main Funktion ruft die crypt class auf und dort passiert alles weitere.</br>

<strong> 3  Funktionsweise </strong>

Initialisierung:</br>
  S-Box, Inverse S-Box & Transpositions Tablle initialisieren</br>
  Diverse Variablen deklarieren</br>
    
//fillKnowns()</br>
  5 Rundenschlüssel mit jeweils 16-Bit Länge generieren </br>
  2^16 Klartexte mit jeweils 16-Bit Länge generieren</br>
  Plaintext in 4 Runden verschlüsseln</br>
    -> 2^16 Known plaintext Paare </br>
      
//findApprox(), applyMask(), showApprox()</br>
  Approximationstabelle für 4 Bit Input & 4 Bit Output generieren</br>
  
//findPartKeys()  </br>
  Wähle Gleichungen nach Matsuis Algorithmus mit hoher Abweichung</br>
    Hier nicht dynamisch implementiert, sondern </br>
      Runde 1: Input: 11, Output: 4</br>
      Runde 2: Input: 4,  Output: 5</br>
      Runde 3: Input: 4,  Output: 5</br>
      Runde 4: Input: 4,  Output: 5</br>
    Abweichung jeweils 1/4. Kumuliert mit Piling-Up Lemma 1/32</br>

  Finale Gleichung mit allen Known-plaintext Paaren testen.</br>

//showPartTable(), getIndexOfHighestValue()</br>
  Ergebnis in Tabelle festhalten und Wert mit höchster Abweichung von 1/2 entspricht gesuchtem Schlüsselbit</br>

Ausgabe der Schlüsselbits 5-8 & 13-16 des Teilschlüssels der 5.Runde in Hexadezimalzahlen</br>


<strong> 4	Konfigurationsdetails </strong>

Die Verschlüsselung kann in folgenden Punkten leicht angepasst werden:
- Substitution (S-Box) //int[] sBox
- Transposition       //int[] transTable
- Anzahl der Known-Plaintext Paare //int numKnown
- Anzahl der Runden  // int numRounds





<strong> 5 Performancebetrachtung </strong>

Die Laufzeit des Algorithmus ist abhängig von der Anzahl der generierten Plaintext-Paare (standard = 2^16)</br>
Obwohl keine theorethische bzw. praktische Laufzeitanalyse gemacht wurde, wird vermutet dass der Algorithmus in Java niemals seine volle Performance erreichen kann.
Auf Grund der umständlichen Behandlung von Binärzahlen in Java bleibt stets ein Overhead bestehen.

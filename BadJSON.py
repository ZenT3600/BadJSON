#/usr/bin/env python3

"""
# BadJSON
### Weaponizing JSON Files

> Matteo Leggio, 2021, MatteoLeggio.it
"""

from random import choice, randint

import collections
import logging
import verboselogs
import json
import string
import time
import click


########## ENIGMA START ###########

class Alfabeto:
    """
    Classe: Alfabeto
    Attributi:
        tasti (dizionario indice:chiave)
        tasti_inversi (dizionario chiave:indice)
    Metodi:
        None
    """

    def __init__(self, caratteri):
        self.caratteri = caratteri
        for carattere in caratteri:
            if caratteri.count(carattere) > 1:
                raise ValueError("L'alfabeto non può contenere doppioni")

    def lunghezza(self):
        return len(self.caratteri)

    def isValid(self, carattere):
        return carattere in self.caratteri

    def indice(self, carattere):
        return self.caratteri.index(carattere)

    def carattere(self, indice):
        return self.caratteri[indice]


class Rotore:
    def __init__(self, connessioni):
        self.connessioni = connessioni
        self.rotazioni = 0

    def ruota(self, n):
        temp = self.connessioni[0:n]
        size = len(self.connessioni)
        for i in range(n, size):
            self.connessioni[i - n] = self.connessioni[i]
        for i in range(0, len(temp)):
            self.connessioni[size - n + i] = temp[i]
        self.rotazioni = (self.rotazioni + n) % len(self.connessioni)

    def restituisci_destra(self, indice):
        return self.connessioni[indice]

    def restituisci_sinistra(self, indice):
        return self.connessioni.index(indice)


class Riflessore:
    """
    Classe: Riflessore
    Attributi:
        connessioni (connessioni interne del riflessore)
    Metodi:
        rifletti (riflette un carattere ad un determinato indice basandosi sulle proprio connessioni interne)
    """

    def __init__(self, connessioni):
        self.connessioni = connessioni

    def rifletti(self, indice):
        """
        Metodo: rifletti
        Descrizione: riflette un carattere ad un determinato indice basandosi sulle proprio connessioni interne
        Parametri: indice
        """
        return indice + self.connessioni[indice]


class Enigma:
    """
    Classe: Enigma
    Attributi:
        shift (posizione di partenza dei rotori)
        tastiera (oggetto tastiera)
        rotori (lista contenente 'n' oggetti rotore)
        riflessore (oggetto riflessore)
    Metodi:
        configura (riconfigura la posizione dei rotori)
        cifra (cifra o decifra un messaggio, senza bisogno che il messaggio sia dichiarato leggibile o cifrato)
    """

    def __init__(self, alfabeto, shift, rotori, riflessore):
        self.alfabeto = alfabeto
        self.rotori = rotori
        self.rotori[0].ruota(shift[0])
        self.rotori[1].ruota(shift[1])
        self.rotori[2].ruota(shift[2])
        self.riflessore = riflessore
        self.scatti = [0, 0, 0]
        self.configura(shift)

    def configura(self, shift):
        shift = [int(s) for s in shift]
        for i, s in enumerate(shift):
            while self.rotori[i].rotazioni != s:
                self.rotori[i].ruota(1)
        self.scatti = [0, 0, 0]

    def cifra(self, msg):
        """
        Metodo: cifra
        Descrizione: cifra o decifra un messaggio, senza bisogno che il messaggio sia dichiarato leggibile o cifrato
        Parametri: msg
        """

        crt = []
        for m in msg:
            if self.alfabeto.isValid(m):
                c = self.alfabeto.indice(m)

                for r in self.rotori:
                    c = r.restituisci_destra(c)

                c = self.riflessore.rifletti(c)

                for r in reversed(self.rotori):
                    c = r.restituisci_sinistra(c)

                crt.append(self.alfabeto.carattere(c))

                self.rotori[0].ruota(1)
                self.scatti[0] += 1
                if self.scatti[0] % self.alfabeto.lunghezza() == 0:
                    self.rotori[1].ruota(1)
                    self.scatti[1] += 1
                    if self.scatti[1] % self.alfabeto.lunghezza() == 0:
                        self.rotori[2].ruota(1)
                        self.scatti[2] += 1

            else:
                crt.append(m)

        # print(self.scatti)
        return "".join(crt)


########## ENIGMA END ###########


class VerboseLogger(verboselogs.VerboseLogger):
    def disabledMessage(self):
        super(VerboseLogger, self).debug(
            "<| Level 3 or Higher Verbose Logging Has Been Disabled. Re-enabling it should be a trivial task for a developer. This is a needed security measure |>")

    def spam(self, msg, *args, **kw):
        self.disabledMessage()

    def debug(self, msg, *args, **kw):
        self.disabledMessage()


logger = VerboseLogger("DefaultLogger")
logger.addHandler(logging.StreamHandler())


def initializeEnigma():
    cables = [
        [27, 23, 35, 7, 33, 61, 15, 52, 49, 25, 12, 77, 32, 68, 88, 63, 69, 83, 10, 17, 16, 14, 78, 4, 59, 62, 79, 76,
         66, 72, 74, 58, 8, 65, 51, 42, 0, 81, 92, 82, 60, 93, 18, 46, 64, 22, 36, 21, 73, 9, 55, 11, 24, 29, 28, 2, 70,
         53, 40, 48, 87, 3, 71, 56, 50, 45, 1, 20, 80, 54, 38, 37, 26, 6, 5, 41, 47, 75, 44, 30, 43, 34, 19, 57, 90, 31,
         86, 85, 13, 39, 91, 89, 84, 67],
        [28, 1, 67, 5, 52, 65, 20, 54, 60, 44, 74, 66, 39, 0, 49, 82, 24, 90, 87, 77, 42, 55, 14, 45, 64, 40, 48, 36, 8,
         59, 71, 11, 16, 46, 89, 57, 83, 12, 13, 75, 92, 38, 4, 43, 10, 47, 58, 7, 37, 79, 69, 30, 41, 17, 62, 73, 25,
         61, 84, 85, 6, 68, 51, 21, 29, 91, 76, 63, 22, 93, 53, 18, 19, 88, 23, 2, 33, 80, 31, 56, 81, 34, 15, 70, 9,
         27, 50, 72, 26, 32, 3, 86, 78, 35],
        [53, 71, 22, 87, 6, 5, 37, 13, 15, 41, 39, 56, 48, 45, 64, 12, 66, 17, 91, 1, 26, 25, 79, 57, 38, 81, 60, 8, 24,
         36, 84, 59, 10, 40, 19, 74, 69, 14, 20, 54, 16, 23, 77, 52, 28, 43, 90, 89, 75, 9, 76, 83, 3, 61, 46, 44, 35,
         85, 63, 70, 47, 18, 4, 49, 42, 78, 58, 2, 31, 21, 30, 55, 27, 50, 82, 7, 93, 73, 33, 29, 72, 65, 32, 51, 68,
         86, 11, 88, 0, 67, 80, 34, 92, 62]]
    reflector = []
    for i in reversed(range(0, len(cables[0]), 2)):
        reflector.append(i + 1)
    for i in range(0, len(cables[0]), 2):
        reflector.append(-i - 1)
    alphabet = Alfabeto(
        list(string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation))
    enigma = Enigma(
        alphabet,
        [0, 0, 0],
        [
            Rotore(
                cables[0]
            ),
            Rotore(
                cables[1]
            ),
            Rotore(
                cables[2]
            )
        ],
        Riflessore(
            reflector
        )
    )
    return enigma


def recursiveEncryption(line, dicti=None, key=None):
    if len(line) == 1 and dicti is None:
        return {line: ""}

    if len(line) == 2 and dicti is None:
        return {line[0]: line[1]}

    if len(line) == 1:
        dicti[key] = line
        return dicti

    if not isinstance(dicti, dict):
        return recursiveEncryption(line[1:], dicti={}, key=line[0])
    else:
        dicti[key] = {}
        recursiveEncryption(line[1:], dicti=dicti[key], key=line[0])
        return dicti


def generateCredibleNoise():
    alphabet = string.ascii_lowercase + string.ascii_uppercase + string.punctuation
    return recursiveEncryption(
        choice(alphabet) + choice(string.digits) + "".join([choice(alphabet) for _ in range(randint(4, 14))]))


def assertKeyExistence(dictionary, key):
    (lambda x: print(end=""))(dictionary[key])


def hide(file, output, enigma, key, binary):
    logger.spam(f"[{time.time()}] Configuring Enigma Object")
    enigma.configura(key)

    logger.debug(f"[{time.time()}] Reading Input File")
    if not binary:
        logger.spam(f"[{time.time()}] File Contains Binary Content")
        with open(file, "r") as f:
            lines = f.readlines()
    else:
        logger.spam(f"[{time.time()}] File Contains PlainText Content")
        with open(file, "rb") as f:
            lines = [str(c) for c in f.read()]
    logger.spam(f"[{time.time()}] A Total Of {len(lines)} Lines Was Found")

    logger.debug(f"[{time.time()}] Encrypting Lines")
    encryptedLines = []
    for line in lines:
        betterLine = line
        encryptedLines.append(enigma.cifra(betterLine))

    rangeList = list(range(0, len(encryptedLines)))

    alphabet = string.ascii_lowercase + string.ascii_uppercase + string.punctuation

    outerDict = {}
    listIndex = 0
    logger.debug(f"[{time.time()}] Nesting Encrypted Lines")
    for i in rangeList:
        listIndex = int(str(i)[:-1]) if len(str(i)) > 1 else 0
        logger.spam(f"[{time.time()}] Asserting Key Existence")
        try:
            # Check if key exists
            assertKeyExistence(outerDict, listIndex)
            assertKeyExistence(outerDict, -(listIndex + 1))
            logger.spam(f"[{time.time()}] Key Exixsts")
        except Exception:
            outerDict[listIndex] = []
            outerDict[-(listIndex + 1)] = []
            logger.spam(f"[{time.time()}] Key Does Not Exist")

        logger.spam(f"[{time.time()}] Appending Nested Data")
        outerDict[listIndex].append(
            {encryptedLines[i][0]: recursiveEncryption(str(i)[-1] + encryptedLines[i][1:].strip())}
        )

        logger.spam(f"[{time.time()}] Appending Nested Noise")
        outerDict[listIndex].append(
            {choice(alphabet): generateCredibleNoise()}
        )

        for _ in range(2):
            outerDict[-(listIndex + 1)].append(
                {choice(alphabet): generateCredibleNoise()}
            )

    # Last listIndex value
    maxIndex = listIndex

    logger.debug(f"[{time.time()}] Generating Noise")
    for i in range(len(list(outerDict.keys()))):
        outerDict[maxIndex + 2 + i] = [generateCredibleNoise() for _ in range(randint(7 * 2, 10 * 2))]

    logger.debug(f"[{time.time()}] Dumping Data To File")
    # noinspection PyTypeChecker
    od = collections.OrderedDict(sorted(outerDict.items()))
    with open(output, "w") as f:
        json.dump(od, f, indent=4)


def recursiveDecryption(dicti, text=""):
    if isinstance(dicti, dict):
        return text + recursiveDecryption(dicti[list(dicti.keys())[0]], text=list(dicti.keys())[0])
    else:
        return text + dicti


def show(file, output, enigma, key, binary):
    logger.spam(f"[{time.time()}] Configuring Enigma Object")
    enigma.configura(key)

    logger.debug(f"[{time.time()}] Reading Input File")
    with open(file, "r") as f:
        jsonDict = json.load(f)

    logger.spam(f"[{time.time()}] Finding Max Reliable Index")
    maxReliable = 0
    missing = [ele for ele in range(max([int(key) for key in jsonDict.keys()]) + 1) if
               ele not in [int(key) for key in jsonDict.keys()]]
    if len(missing):
        maxReliable = missing[0] - 1

    logger.debug(f"[{time.time()}] Decrypting Json Data")
    text = {}
    for outerK in jsonDict.keys():
        if not outerK.isnumeric():
            # Is noise
            logger.spam(f"[{time.time()}] Skipping Noise")
            continue

        if int(outerK) < 0:
            # Is noise
            logger.spam(f"[{time.time()}] Skipping Noise")
            continue

        if int(outerK) > maxReliable:
            # Is noise
            logger.spam(f"[{time.time()}] Skipping Noise")
            continue

        innerList = jsonDict[outerK]
        for i, dicti in enumerate(innerList):
            firstKey = list(dicti.keys())[0]
            secondKey = list(dicti[firstKey].keys())[0]

            if not secondKey.isnumeric():
                continue

            logger.spam(f"[{time.time()}] Denesting Data")
            denested = recursiveDecryption(dicti[firstKey])
            text[int(outerK + secondKey)] = firstKey + denested[1:]

    logger.debug(f"[{time.time()}] Decrypting Data")
    # noinspection PyTypeChecker
    od = collections.OrderedDict(sorted(text.items()))
    decipheredText = []
    for k, v in od.items():
        decipheredText.append(enigma.cifra(v))

    logger.debug(f"[{time.time()}] Dumping Data To File")
    if not binary:
        logger.spam(f"[{time.time()}] Data Contains PlainText Content")
        with open(output, "w") as f:
            f.write("\n".join([line if len(line.strip()) else "" for line in decipheredText]))
    else:
        logger.spam(f"[{time.time()}] Data Contains Binary Content")
        with open(output, "wb") as f:
            f.write(bytearray([int(c) for c in decipheredText]))


def generateValidKey(key, enigma):
    return [int((ord(char) ** (i + 1)) % (len(enigma.alfabeto.caratteri) - 1)) for i, char in enumerate(key * 3) if
            i < 3]


@click.command()
@click.option('--show', 'action', flag_value='show', help="ACTION: Show the contents of a BadJSON file")
@click.option('--hide', 'action', flag_value='hide', help="ACTION: Hide your data in a BadJSON file")
@click.option("--inputfile", "-i", required=True, type=str, help="The input file")
@click.option("--outputfile", "-o", required=True, type=str, help="The output file")
@click.option("--key", "-k", required=True, type=str, help="The encryption key")
@click.option("--binary", "-b", is_flag=True, help="FLAG: Wether the file is PlainText of Binary data")
@click.option("--verbose", "-v", count=True, help="STACKABLE: The verbosity level of the logs")
def main(action, outputfile, inputfile, key, binary, verbose):
    global logger

    if not action:
        logger.warning("No Action Specified, Quitting...")
        return

    logger.setLevel(
        (logging.WARNING, logging.NOTICE, logging.VERBOSE, logging.DEBUG, logging.SPAM)[verbose if verbose <= 4 else 4])
    logger.verbose(f"[{time.time()}] Program Started")

    e = initializeEnigma()

    if action == "hide":
        logger.notice(f"[{time.time()}] Hiding file \"{inputfile}\" into \"{outputfile}\"")
        logger.verbose(f"[{time.time()}] Key: {key}")
        logger.verbose(f"[{time.time()}] Verbose: {verbose}")
        logger.verbose(f"[{time.time()}] Is Binary: {binary}")

        hide(inputfile, outputfile, e, generateValidKey(key, e), binary)
    elif action == "show":
        logger.notice(f"[{time.time()}] Showing file \"{inputfile}\" into \"{outputfile}\"")
        logger.verbose(f"[{time.time()}] Key: {key}")
        logger.verbose(f"[{time.time()}] Verbose: {verbose}")
        logger.verbose(f"[{time.time()}] Is Binary: {binary}")

        show(inputfile, outputfile, e, generateValidKey(key, e), binary)

    logger.verbose(f"[{time.time()}] Program Ended")


if __name__ == '__main__':
    main()

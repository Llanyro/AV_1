#!/usr/bin/env python3
import hashlib
import magic
import mimetypes
import os
import platform
import subprocess
import time
from virus_total_apis import PublicApi
from Core.AI import AIScan
from Core.DatabaseController import MalwareControllerDB, FrasesMalware


class BinaryAnalysisCore:
    # region Var e init
    __malware_controller: MalwareControllerDB
    __public_api: PublicApi
    __read_file_size: int = 1024
    __sleep_time: int = 16  # Tiempo en volver a hacer una peticion a virustotal (4 por min)

    def __init__(self):
        self.__public_api = PublicApi("9937e4389b47e585c379961a9c932e29cd99486ca7fe739c56e2ca9b7c62afeb")
        # self.__malware_controller = MalwareController("Core/database.csv")
        self.__malware_controller = MalwareControllerDB("Core/database.sav")

    # endregion
    # region Virustotal
    def __scan_virus_total(self, filename: str) -> dict:
        """
        Virustotal escanea un fichero nuevo y devuelve el resultado del analisis
        """
        return self.__public_api.scan_file(filename)

    def __search_virus_total(self, hash_dict: dict) -> dict:
        """
        Virustotal devuelve un analis de un binario ya analizado previamente(Solo consulta a sus bases de datos)
        """
        return self.__public_api.get_file_report([hash_dict["sha256"], hash_dict["sha1"], hash_dict["md5"]])

    def __virutotal_results_to_list(self, results: dict) -> list:
        # Se ha excedido el numero de peticiones por min
        if results["response_code"] == 204:
            print("Se procede a esperar 1 min para hacer otra peticion")
            time.sleep(60)
        resultados: list = []
        res: list = results["results"]
        for i in res:
            if i["response_code"] == 1:
                resultados.append(True)
            else:
                resultados.append(False)
        return resultados

    def run_virutotal(self, filename: str, hash_dict: dict, already_sent: bool = False) -> dict:
        # Probamos que virustotal tenga el binario en su base de datos
        resultado_busqueda_virustotal = self.__search_virus_total(hash_dict)
        #print(resultado_busqueda_virustotal)

        # Transformamos el diccionario en una lista de True-False para saber si se contiene algun analisis
        resultado_listado: list = self.__virutotal_results_to_list(resultado_busqueda_virustotal)
        #print(resultado_listado)

        # Si no se ha recibido al menos un analisis
        if any(resultado_listado) is not True:
            self.__scan_virus_total(filename)
            time.sleep(self.__sleep_time)
            # Ya se ha dejado tiempo para que virustotal procese el binario
            # Procedemos a realizar el mismo proceso
            return self.run_virutotal(filename, hash_dict, True)
        # Si ya se ha procesado un binario con el hash y nos ha devuelto el analisis
        # Solo nos quedamos con el analisis de un hash(todos deberian ser el mismo)
        # Nos quedamos con sha256 ya que es el menos probable de error
        result_sha256: dict = resultado_busqueda_virustotal["results"][0]
        for i in resultado_busqueda_virustotal["results"]:
            if i["sha256"] == hash_dict["sha256"]:
                result_sha256 = i
                break
        return result_sha256

    # endregion
    # region Chkrootkit
    def __scan_chkrootkit(self, filename: str):
        if platform.system() == "Linux":
            pass
        elif platform.system() == "Darwin":
            print("No testeado para mac os")
        elif platform.system() == "Windows":
            print("NO compatible con sistemas nt (Windows)")

    # endregion
    # region Capabilities
    def scan_capa(self, filename: str):
        if os.path.exists(filename) and os.path.isfile(filename):
            command: str = ""
            if platform.system() == "Linux":
                command = "./Antivirus/binaries/capa_linux"
            elif platform.system() == "Darwin":
                command = "./Antivirus/binaries/capa_mac"
            elif platform.system() == "Windows":
                command = "./Antivirus/binaries/capa.exe"
            else:
                print("No se ha detectado binario disponible de capa para el sistema", platform.system())

            if command.__len__() != 0:
                out = subprocess.Popen([command, filename], stdout=subprocess.PIPE)
                stdout, stderr = out.communicate()
                print(stdout.decode("utf8"))
        else:
            print(f"El archivo o path '{filename}' no existe")

    def __git_capa(self):
        print("Capa url: https://github.com/fireeye/capa")

    # endregion
    # region Magic
    def __magic_extension_type(self, filename: str) -> dict:
        """
        Devuelve si la extension del archivo es igual que el que parece pertener segun puremagic
        :param filename:
        :return:
        {
        mimetype: Tipo de archivo tipo mime
        extension: Extension del archivo
        magic: Si todo esta correcto
        mime_extension: Extension recibidad de mime
        }
        """
        # Magic number
        result: dict = {"mimetype": magic.from_file(filename, mime=True), "magic": False}

        # Obtenemos solo el archivo a analizar
        r: str = filename.rsplit("/", 1)[-1]
        # Si empieza por "." lo eliminamos
        if r.startswith("."):
            r = r[1:]
        # Si sigue conteniendo extension
        if r.__contains__("."):
            result.update({"extension": r.split(".", 1)[-1]})
        # Si no contiene extension
        else:
            result.update({"extension": None})

        result.update({"mime_extension": mimetypes.guess_extension(result["mimetype"], strict=True)})

        # Si parece un .exe
        if result["mimetype"] == "application/x-dosexec":
            if result["extension"] == ".exe":
                result.update({"magic": True})
        # Si la extension prevista y la extension son iguales
        elif result["mime_extension"] == result["extension"]:
            result.update({"magic": True})
        # Si es un archivo extraño de texto
        elif result["mimetype"] is not None and result["extension"]\
                and result["mimetype"].__contains__(result["extension"]):
            result.update({"magic": True})

        return result

    # endregion
    # region Other
    def get_hashes(self, filename: str) -> dict:
        """
        Dado un nombre de un fichero, genera un hash con sha1 y md5
        :param filename: Nombre del fichero a analizar
        :return: Hashes [md5 y sha1] en una lista
        """
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(filename, 'rb') as f:
            while True:
                data = f.read(self.__read_file_size)
                if not data:
                    break
                md5.update(data)
                sha1.update(data)
                sha256.update(data)
                if data.__len__() < self.__read_file_size:
                    break
        return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}

    def save(self):
        self.__malware_controller.export()

    # endregion
    # region Analizadores
    def __all_scans_detect_something(self, result: dict) -> bool:
        """
        Devuelve True si todos los analizadores han evaludado algo
        :param result:
        :return:
        """
        return all([True if result["detected_by"][i] is not None else False for i in result["detected_by"]])

    def run_analysis(self, filename: str, virustotal: bool = False, ai_1: bool = False, magic_ext: bool = False, save: bool = True, reanalisis: bool = False) -> dict:
        # Obtenemos los hashes del fichero a analizar (Cuidado en no elegir un directorio, quien sabe que puede pasar)
        hash_dict: dict = self.get_hashes(filename)

        result: dict
        # Obtenemos el diccionario vacio si es un reanalisis
        if reanalisis:
            result = self.__malware_controller.get_data_hash_empty(hash_dict)
        # Buscamos en la base de datos interna para saber si se tiene registrado algo
        else:
            result = self.__malware_controller.get_data_hash(hash_dict)

        # Si se teiene registrado devolvemos el resultado de la base de datos
        # Si no teniamos resultado generado, probamos con virustotal 2ª o 3ª opcion
        if result["in_database"] is not True:
            if virustotal:
                resultado_busqueda_virustotal: dict = self.run_virutotal(filename, hash_dict)

                # Adaptamos el diccionario a nuestra base de datos y lo guardamos
                result.update({
                    # Los hashes ya estan en el diccionario
                    "date": resultado_busqueda_virustotal["scan_date"],
                    "virustotal_link": resultado_busqueda_virustotal["permalink"],
                    "virustotal_results":
                        f"{resultado_busqueda_virustotal['positives']}/{resultado_busqueda_virustotal['total']}"
                })

                # Guardamos el resultado obtenido segun Virustotal
                result["detected_by"].update({
                    "virustotal": self.__malware_controller.is_malware(
                        resultado_busqueda_virustotal['positives'],
                        resultado_busqueda_virustotal['total']).value
                })
                # Si estamos seguro de que es malicioso, lo anotamos ya
                if result["detected_by"]["virustotal"] == FrasesMalware.valor_5_20 or \
                        result["detected_by"]["virustotal"] == FrasesMalware.valor_20:
                    result.update({"malicious": True})

            if magic_ext:
                magic_result: dict = self.__magic_extension_type(filename)
                result.update({
                    "mimetype": magic_result["mimetype"],
                    "mime_extension": magic_result["mime_extension"]
                })
                if magic_result["magic"] == False:
                    result["detected_by"].update({"Magic": "Malicious or wrong extension used"})

                # No anotamos si es malicioso o no, ya que magic solo da informacion

            if ai_1:
                ai = AIScan("AI_1", "Core/AI_1.sav")
                resultado: float = ai.scan_file(filename)
                if resultado == -1:
                    print("Eliminar los archivos *.sav provocan que nas AI no funcionen")
                else:
                    resultado_ai: str = "Puede que este limpio"
                    if resultado >= 0.5:
                        resultado_ai = "Potencialmente malicioso"
                    result["detected_by"].update({"AI_1": resultado_ai})
                    result.update({"AI_1_value_result": str(resultado)})

                    if resultado >= 0.65:
                        result.update({"malicious": True})

            # Si todos los scans han detectado que el binario es malicioso
            if self.__all_scans_detect_something(result):
                result.update({"malicious": True})

            # Lo anadimos a la lista si se quiere
            if save and self.__malware_controller.add_hash_database(result) is True:
                result.update({"in_database": True})
        return result

    # endregion

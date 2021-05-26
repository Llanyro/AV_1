#!/usr/bin/env python3
import os
from datetime import date
from SimplePythonLogger.logger import Logger
from enum import Enum
from json import load, loads, dump, dumps


# region Enums
class FrasesMalware(Enum):
    unknown = "Unknown"
    valor_0 = "Probablemente no malicioso"
    valor_1_5 = "Probablemente no malicioso o preparado para no ser detectado"
    valor_5_20 = "Peligroso"
    valor_20 = "Potencialmente peligroso"


class FrasesTipo(Enum):
    same = "Mismo tipo"
    different = "No tiene el mismo tipo real que la extension"
    none = "No importa"


# endregion
class MalwareControllerDB:
    # region Varaiables
    __table_columns: list = [
        "md5", "sha1", "sha256",  # Hashes del binario
        "date",  # Fecha del analisis
        "detected_by",  # Quien lo ha detectado como malicioso (None si nadie)
        "malicious",  # Resultado escrito a mano del binario (True-False)
        "mimetype",  # Que tipo de binario es (ELF, pfd etc)
        "mime_extension",  # Que tipo de binario es (ELF, pfd etc)
        "AI_1_value_result",
        "virustotal_link", "virustotal_results",  # Link de virustotal y resultado de virustotal (n/??)
    ]
    __database_name: str
    __database_modificada: bool
    __database: list
    __logger: Logger

    # endregion
    # region Constructor
    def __init__(self, database_name: str = "Core/database.sav"):
        self.__database_name = database_name
        self.__logger = Logger("./logs")
        self.__database_modificada = False
        self.__load()

    # endregion
    # region Funcionalidades
    def print(self):
        print(self.__database)

    def hash_exist_in_database(self, hash_dict: dict) -> bool:
        row: int = self.get_row_position(hash_dict)
        if row == -1:
            resultado = False
        elif row >= 0:
            resultado = True
        else:
            print(f"Error de posicion {row}")
            resultado = False
        return resultado

    def add_hash_database(self, hash_dict: dict) -> bool:
        if self.hash_exist_in_database(hash_dict) is False:
            if self.valid_hash_dict(hash_dict) is False:
                hash_dict = self.generate_new_hash_dict(hash_dict)
            print(hash_dict)
            self.__database.append(hash_dict)
            self.__database_modificada = True
            return True
        return False

    def get_row_position(self, hash_dict: dict) -> int:
        row: int = -1
        for i in range(self.__database.__len__()):
            if self.__database[i]["md5"] == hash_dict["md5"] and self.__database[i]["sha1"] == hash_dict["sha1"] and self.__database[i]["sha256"] == hash_dict["sha256"]:
                row = i
                break
        return row

    def update_row(self, row: dict) -> bool:
        position: int = self.get_row_position(row)
        if position >= 0:
            del self.__database[position]
            self.__database.append(row)
            self.__database_modificada = True
            return True
        return False

    def get_data_hash(self, hash_dict: dict) -> dict:
        """
        Busca en la base de datos interna si el binario hasheado esta guardado
        :param hash_dict: lista de hashes [md5, sha1]
        :return: Si existe en la base de datos
        """
        result: dict = self.get_data_hash_empty(hash_dict)
        # Obtenemos la row y a la vez, si esta en la basse de datos
        row: int = self.get_row_position(hash_dict)
        # Si esta en la base de datos, la row no es None
        if row >= 0:
            fila: dict = self.__database[row]
            # Obtenemos datos del hash
            result.update({
                    "in_database": True,
                    "date": fila["date"],
                    "malicious": fila["malicious"],
                    "detected_by": fila["detected_by"],
                    "virustotal_link": fila["virustotal_link"],
                    "virustotal_results": fila["virustotal_results"],
                    "mime_extension": fila["mime_extension"],
                    "AI_1_value_result": fila["AI_1_value_result"],
                    "mimetype": fila["mimetype"]
                })
        return result

    def get_data_hash_empty(self, hash_dict) -> dict:
        return {
            "in_database": False,
            "md5": hash_dict["md5"],
            "sha1": hash_dict["sha1"],
            "sha256": hash_dict["sha256"],
            "malicious": False,
            "detected_by": {}
        }

    def export(self) -> None:
        if self.__database_modificada:
            print("Database modificada.\nExportando datos...")
            with open(self.__database_name, "w") as f:
                dump(dumps({"database": self.__database}), f)
        else:
            print("Database no modificada\nNo se exportara nada")

    def __load(self):
        # Si existe la base de datos
        if os.path.exists(self.__database_name):
            with open(self.__database_name, "r") as f:
                self.__database = loads(load(f))["database"]
        else:
            self.__database = []

    def valid_hash_dict(self, hash_dict: dict) -> bool:
        result: list = []
        # Si lo que hay en el diccionario esta en la lista
        for i in hash_dict:
            result.append(i in self.__table_columns)
        # Si lo que hay en la lista esta en el diccionario
        for i in self.__table_columns:
            result.append(i in hash_dict)
        return all(result)

    def generate_new_hash_dict(self, hash_dict: dict):
        result: dict = {}
        # Por cada elemento
        for i in hash_dict:
            # Si es peteneciente a la tabla
            if i in self.__table_columns:
                # Se añade al nuevo diccionario
                result.update({i: hash_dict[i]})
        # Por cada elemento de la lista
        for i in self.__table_columns:
            # Si un elemento no existe
            if i not in hash_dict:
                if i == "date":
                    result.update({"date": date.today().strftime("%d/%m/%Y")})
                elif i == "detected_by":
                    result.update({
                        "detected_by": {
                            "AI_1": None,
                            "virustotal": None,
                            "Magic": None
                        }
                    })
                elif i == "malicious":
                    result.update({"malicious": False})

                elif i == "mime_extension":
                    result.update({"mime_extension": None})
                elif i == "mimetype":
                    result.update({"extension": "text/plain"})

                elif i == "virustotal_link":
                    result.update({"virustotal_link": "None"})
                elif i == "virustotal_results":
                    result.update({"virustotal_results": "??/??"})

                elif i == "AI_1_value_result":
                    result.update({"AI_1_value_result": 0})

                else:
                    raise Exception(f"La columna {i}, no esta contenida en el diccionario: {hash_dict}.\n"
                                    f"Esto genera un error y para el programa")
        return result

    def is_malware(self, value: float, total: float) -> FrasesMalware:
        """
        ??% Unknown
        0% Probablemente no malicioso
        1-5% Probablemente no malicioso o preparado para no ser detectado
        5-20% Peligroso
        20%> Potencialmente peligroso
        """
        res: float = ((value * 100) / total)
        if res < 1:
            return FrasesMalware.valor_0
        elif 1 < res <= 5:
            return FrasesMalware.valor_1_5
        elif 5 < res <= 20:
            return FrasesMalware.valor_5_20
        else:
            return FrasesMalware.valor_20

    # endregion

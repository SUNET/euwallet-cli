#!/usr/bin/env python3
import typer
from client import main as client_main
from pydantic import BaseModel
from typing_extensions import Annotated, Optional

app = typer.Typer()

# Define the shared configuration parameter
ConfigOption = Annotated[
    str, typer.Option(help="Path to the configuration file", default="config.yaml")
]


def common_config_options(
    config_path: ConfigOption = "config-test.yaml",
):
    return config_path


class PID(BaseModel):
    document_type: str = "PersonIdentificationData"


class EHIC(BaseModel):
    document_type: str = "EHIC"
    collect_id: str = "collect_id_ehic_122"
    authentic_source: str = "EHIC:00001"


class PDA1(BaseModel):
    document_type: str = "PDA1"
    collect_id: str = "collect_id_pda1_122"
    authentic_source: str = "PDA1:00001"


def authentic_source_callback(
    ctx: typer.Context, param: typer.CallbackParam, value: str
):
    """
    The default values for Credentials are set for vc-interop
    Databases
    """
    if ctx.resilient_parsing:
        return  # skipping check on default commands
    print(f"Validating param: {param.name}")
    if ctx.info_name == "ehic":
        if value[:4].lower() != "ehic":
            raise typer.BadParameter("Only EHIC authentic source is allowed")
    if ctx.info_name == "pda1":
        if value[:4].lower() != "pda1":
            raise typer.BadParameter("Only PDA1 authentic source is allowed")
    if ctx.info_name == "pid":
        if value[:4].lower() != "pid":
            raise typer.BadParameter("Only PID authentic source is allowed")
    return value


@app.command()
def ehic(
    issuer_to_use: Optional[str] = None,
    collect_id: Annotated[
        str, typer.Option(help="EHIC document id in the database")
    ] = "collect_id_ehic_122",
    authentic_source: Annotated[
        str,
        typer.Option(
            help="EHIC document id in the database", callback=authentic_source_callback
        ),
    ] = "EHIC:00001",
    config_path: str = common_config_options(),
):
    document_type = "EHIC"

    ehic = EHIC(
        document_type=document_type,
        collect_id=collect_id,
        authentic_source=authentic_source,
    )
    document = ehic.model_dump()
    client_main(config_path, document, issuer_to_use)


@app.command()
def pda1(
    issuer_to_use: Optional[str] = None,
    collect_id: Annotated[
        str, typer.Option(help="PDA1 document id in the database")
    ] = "collect_id_pda1_122",
    authentic_source: Annotated[
        str,
        typer.Option(
            help="PDA1 document id in the database", callback=authentic_source_callback
        ),
    ] = "PDA1:00001",
    config_path: str = common_config_options(),
):
    document_type = "PDA1"

    ehic = PDA1(
        document_type=document_type,
        collect_id=collect_id,
        authentic_source=authentic_source,
    )
    document = ehic.model_dump()
    client_main(config_path, document, issuer_to_use)


@app.command()
def pid(
    config_path: str = common_config_options(), issuer_to_use: Optional[str] = None
):
    document = PID()
    print(document.model_dump())
    document_type = "PersonIdentificationData"
    client_main(config_path, None, issuer_to_use, document_type)


@app.command()
def verifier():
    # implement late the flow
    raise NotImplementedError


@app.command()
def run_all():
    """Run all commands sequentially."""
    print("\n--- Running EHIC ---")
    ehic()

    print("\n--- Running PDA1 ---")
    pda1()

    print("\n--- Running PID ---")
    pid()


if __name__ == "__main__":
    app()

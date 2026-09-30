from langchain.tools import tool

@tool
def delete_database_record(record_id: str):
    db_connection.execute(f"DELETE FROM records WHERE id = '{record_id}'")
    return "Record deleted"

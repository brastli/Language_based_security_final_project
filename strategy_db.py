import sqlite3
import os

class StrategyDB:
    """
    SurgicalPatch 的策略进化知识库
    负责持久化存储 LLM 在沙箱对抗中总结出的有效漏洞修复策略。
    """
    def __init__(self, db_path="vulnerability_strategies.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.create_table()

    def create_table(self):
        # 存储 CWE ID、具体的修复策略文本、成功次数
        query = """
        CREATE TABLE IF NOT EXISTS cwe_strategies (
            cwe_id TEXT PRIMARY KEY,
            strategy_text TEXT,
            success_count INTEGER DEFAULT 0
        )
        """
        self.conn.execute(query)
        self.conn.commit()

    def get_strategy(self, cwe_id):
        """
        根据 CWE 编号查询已验证的成功策略
        """
        cursor = self.conn.execute("SELECT strategy_text FROM cwe_strategies WHERE cwe_id = ?", (str(cwe_id),))
        row = cursor.fetchone()
        return row[0] if row else None

    def save_strategy(self, cwe_id, strategy_text):
        """
        保存或更新有效策略。如果 CWE 已存在，则覆盖最新策略并增加成功计数。
        """
        query = """
        INSERT INTO cwe_strategies (cwe_id, strategy_text, success_count)
        VALUES (?, ?, 1)
        ON CONFLICT(cwe_id) DO UPDATE SET 
            strategy_text = excluded.strategy_text,
            success_count = success_count + 1
        """
        self.conn.execute(query, (str(cwe_id), strategy_text))
        self.conn.commit()
        
    def get_success_count(self, cwe_id):
        """辅助方法：获取某个策略被成功验证的次数"""
        cursor = self.conn.execute("SELECT success_count FROM cwe_strategies WHERE cwe_id = ?", (str(cwe_id),))
        row = cursor.fetchone()
        return row[0] if row else 0
        
    def close(self):
        self.conn.close()
import sqlite3
import os

def view_strategies(db_path="vulnerability_strategies.db"):
    if not os.path.exists(db_path):
        print(f"找不到数据库文件: {db_path}")
        print("请确保流水线 (main.py) 已经至少成功修复过一个漏洞并保存了策略。")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT cwe_id, success_count, strategy_text FROM cwe_strategies ORDER BY success_count DESC")
        rows = cursor.fetchall()

        if not rows:
            print("策略库目前为空。")
            return

        print("=" * 80)
        print(f" 🧠 SurgicalPatch 策略进化知识库 (共 {len(rows)} 条)")
        print("=" * 80)

        for row in rows:
            cwe_id, success_count, strategy_text = row
            print(f"\n🎯 [CWE-{cwe_id}] (历史成功应用次数: {success_count})")
            print("-" * 80)
            print(strategy_text.strip())
            print("-" * 80)

    except sqlite3.Error as e:
        print(f"读取数据库时发生错误: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    view_strategies()
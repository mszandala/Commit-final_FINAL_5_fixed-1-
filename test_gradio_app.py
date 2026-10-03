import html
import json
import os
import sys
from pathlib import Path

# Dołączenie folderu backend do ścieżki Pythona
BACKEND_DIR = Path(__file__).parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import gradio as gr

import pipeline
from config import (LLM_PROVIDER, MODEL, PII_JUDGE_ENABLED, PII_MODEL, ROLES, SECURITY_MODEL,
                    SECURITY_PROVIDER, SETTINGS)
from security.pii.gliner_detector import detect_gliner_pii
from security.pii.pii_detector import detect_pii
from security.pii.regex_detector import detect_regex_pii

# Stan historii czatu w formacie Gradio
chat_history_state = []
conversation = None

DEFAULT_ROLE = "podstawowy użytkownik"
EVENTS_PLACEHOLDER = "<div style='color: #64748b; padding: 12px; border: 1px dashed #cbd5e1; border-radius: 8px;'>Tu pojawi się log audytu ostatniej tury z podziałem na strefy...</div>"
TOOLS_PLACEHOLDER = "<div style='color: #64748b; padding: 12px; border: 1px dashed #cbd5e1; border-radius: 8px;'>Tu pojawią się wywołania narzędzi z ostatniej odpowiedzi...</div>"


def role_info(role: str) -> str:
    """Opis roli i lista narzędzi z jej whitelisty."""
    cfg = ROLES[role]
    tools = ", ".join(f"`{t}`" for t in cfg["allowed_tools"])
    return f"{cfg['description']}\n\n**Dozwolone narzędzia:** {tools}"


def format_tool_calls_html(role: str, calls: list[dict]) -> str:
    """Formatuje wywołania narzędzi; próby spoza whitelisty roli są wyróżnione jako naruszenia."""
    if not calls:
        return "<div style='color: #64748b; padding: 12px;'>Model nie wywołał żadnego narzędzia.</div>"

    blocked = [c for c in calls if not c["allowed"]]
    items_html = ""
    for c in calls:
        args = html.escape(json.dumps(c["args"], ensure_ascii=False))
        if c["allowed"]:
            bg_col, txt_col, label = "#dcfce7", "#15803d", "✔ DOZWOLONE"
        else:
            bg_col, txt_col, label = "#fee2e2", "#b91c1c", "⛔ ZABLOKOWANE"
        items_html += f"""
        <li style="margin-bottom: 8px; list-style-type: none; padding: 6px 10px; background: white; border-radius: 6px; box-shadow: 0 1px 2px rgba(0,0,0,0.05);">
            <span style="background-color: {bg_col}; color: {txt_col}; font-weight: 700; font-size: 11px; padding: 3px 8px; border-radius: 12px; margin-right: 8px;">{label}</span>
            <strong style="color: #0f172a; font-size: 14px;">{html.escape(c["tool"])}</strong>
            <div style="color: #64748b; font-size: 11px; font-family: monospace; margin-top: 4px;">{args}</div>
        </li>
        """

    role_name = html.escape(role)
    if blocked:
        names = ", ".join(sorted({html.escape(c["tool"]) for c in blocked}))
        header = f"""
        <div style="color: #dc2626; font-weight: 800; font-size: 14px; margin-bottom: 8px;">
            🚨 Model próbował wywołać narzędzie nieprzypisane do roli „{role_name}”: {names}.
            Wywołanie zablokowano, model odpowiadał bez tych danych.
        </div>
        """
        box = "background-color: #fef2f2; border: 1px solid #fecaca;"
    else:
        header = f"""
        <div style="color: #16a34a; font-weight: bold; margin-bottom: 8px;">
            ✔ Wszystkie wywołania mieszczą się w uprawnieniach roli „{role_name}”.
        </div>
        """
        box = "background-color: #f0fdf4; border: 1px solid #bbf7d0;"

    return f"""
    <div style="padding: 14px; border-radius: 8px; {box} margin-bottom: 12px;">
        {header}
        <ul style="padding-left: 0; margin: 0;">
            {items_html}
        </ul>
    </div>
    """


def format_entities_html(entities: list[dict], title: str) -> str:
    """Formatuje wykryte encje do ładnego bloku HTML z kolorowymi badge'ami."""
    if not entities:
        return f"""
        <div style="padding: 12px; border-radius: 8px; background-color: #f0fdf4; border: 1px solid #bbf7d0; margin-bottom: 12px;">
            <span style="color: #16a34a; font-weight: bold;">✔ {title}:</span>
            <span style="color: #15803d; margin-left: 8px;">Brak wykrytych danych wrażliwych (Czysto)</span>
        </div>
        """

    items_html = ""
    badge_colors = {
        "PASSWORD": ("#fee2e2", "#b91c1c", "🔑"),
        "SALARY": ("#fef3c7", "#b45309", "💰"),
        "ORGANIZATION": ("#e0e7ff", "#4338ca", "🏢"),
        "LOCATION": ("#ecfdf5", "#047857", "📍"),
        "NAME": ("#f3e8ff", "#6b21a8", "👤"),
        "PHONE-NO": ("#e0f2fe", "#0369a1", "📞"),
        "EMAIL": ("#fae8ff", "#a21caf", "✉"),
        "PROJECT": ("#fef08a", "#854d0e", "📁"),
    }

    for e in entities:
        etype = e.get("type", "UNKNOWN")
        bg_col, txt_col, icon = badge_colors.get(etype, ("#f1f5f9", "#334155", "⚠️"))
        items_html += f"""
        <li style="margin-bottom: 8px; list-style-type: none; display: flex; align-items: center; justify-content: space-between; padding: 6px 10px; background: white; border-radius: 6px; box-shadow: 0 1px 2px rgba(0,0,0,0.05);">
            <div>
                <span style="background-color: {bg_col}; color: {txt_col}; font-weight: 700; font-size: 11px; padding: 3px 8px; border-radius: 12px; margin-right: 8px;">
                    {icon} {etype}
                </span>
                <strong style="color: #0f172a; font-size: 14px;">"{e.get('text')}"</strong>
            </div>
            <span style="color: #64748b; font-size: 11px; font-family: monospace;">znaki [{e.get('start')}:{e.get('end')}]</span>
        </li>
        """

    return f"""
    <div style="padding: 14px; border-radius: 8px; background-color: #fef2f2; border: 1px solid #fecaca; margin-bottom: 12px;">
        <div style="color: #dc2626; font-weight: 800; font-size: 14px; margin-bottom: 8px;">
            🚨 ALARM: {title} ({len(entities)} encji):
        </div>
        <ul style="padding-left: 0; margin: 0;">
            {items_html}
        </ul>
    </div>
    """


def format_guard_verdict_html(verdict, role: str) -> str:
    """Formatuje ocenę Prompt Guard do estetycznego bloku HTML."""
    if verdict.has_warning:
        return f"""
        <div style="padding: 12px; border-radius: 8px; background-color: #fffbeb; border: 1px solid #fde68a; margin-bottom: 12px;">
            <div style="color: #b45309; font-weight: 800; font-size: 13px; margin-bottom: 4px;">
                ⚠️ OSTRZEŻENIE PROMPT GUARD (Zapytanie dopuszczone – tryb ostrzeżeń):
            </div>
            <div style="color: #92400e; font-size: 13px;">{html.escape(verdict.reason)}</div>
        </div>
        """
    return f"""
    <div style="padding: 10px 12px; border-radius: 8px; background-color: #f0fdf4; border: 1px solid #bbf7d0; margin-bottom: 12px;">
        <span style="color: #16a34a; font-weight: bold;">✔ Prompt Guard:</span>
        <span style="color: #15803d; margin-left: 8px;">Zapytanie zgodne z uprawnieniami roli '{html.escape(role)}'</span>
    </div>
    """


ZONE_STYLE = {
    "security": ("#ede9fe", "#5b21b6", "STREFA BEZPIECZEŃSTWA"),
    "chatbot": ("#ffedd5", "#9a3412", "STREFA CHATBOTA"),
    "local": ("#dcfce7", "#15803d", "LOKALNIE"),
}
DECISION_LABEL = {"send": "wysłano do chatbota", "mask": "zamaskowano", "block": "zablokowano"}


def format_masking_html(result) -> str:
    """Pokazuje, co faktycznie dostał chatbot, i decyzję dla każdej encji z promptu."""
    rows = "".join(
        f"<li style='list-style-type: none; font-size: 12px; margin-bottom: 4px;'>"
        f"<strong>{html.escape(e['type'])}</strong> „{html.escape(e['text'])}” → {DECISION_LABEL.get(e['decision'], e['decision'])}</li>"
        for e in result.prompt_entities
    ) or "<li style='list-style-type: none; font-size: 12px; color: #64748b;'>Brak danych wrażliwych w prompcie.</li>"
    leak_col, leak_txt = ("#16a34a", "0 — żadna zamaskowana wartość nie trafiła do chatbota") if result.leaks_to_chatbot == 0 \
        else ("#dc2626", f"{result.leaks_to_chatbot} wartości z sejfu trafiło do chatbota")
    out = result.output
    summary = (f"przywrócono: {len(out['restored'])}, ukryto: {len(out['redacted'])}, "
               f"blokada: {len(out['blocked'])}, ze źródeł publicznych / własne: {len(out['exempt'])}")
    return f"""
    <div style="padding: 14px; border-radius: 8px; background-color: #f8fafc; border: 1px solid #cbd5e1; margin-bottom: 12px;">
        <div style="font-weight: 800; font-size: 14px; margin-bottom: 6px; color: #0f172a;">🎭 Prompt wysłany do chatbota</div>
        <div style="font-family: monospace; font-size: 12px; background: white; padding: 8px; border-radius: 6px; color: #0f172a;">{html.escape(result.masked_prompt) or "—"}</div>
        <ul style="padding-left: 0; margin: 8px 0;">{rows}</ul>
        <div style="font-size: 12px; color: {leak_col}; font-weight: 700;">Kontrola przecieku: {leak_txt}</div>
        <div style="font-size: 12px; color: #334155; margin-top: 4px;">Odpowiedź dla użytkownika — {summary}</div>
    </div>
    """


def format_events_html(events: list[dict]) -> str:
    """Zdarzenia audytu tury z oznaczeniem strefy; to samo trafia do audit/events.jsonl."""
    items = ""
    for e in events:
        bg_col, txt_col, label = ZONE_STYLE.get(e["zone"], ("#f1f5f9", "#334155", e["zone"].upper()))
        details = {k: v for k, v in e.items() if k not in ("ts", "type", "zone")}
        items += f"""
        <li style="margin-bottom: 6px; list-style-type: none; padding: 6px 10px; background: white; border-radius: 6px; box-shadow: 0 1px 2px rgba(0,0,0,0.05);">
            <span style="background-color: {bg_col}; color: {txt_col}; font-weight: 700; font-size: 10px; padding: 3px 8px; border-radius: 12px; margin-right: 8px;">{label}</span>
            <strong style="color: #0f172a; font-size: 13px;">{html.escape(e["type"])}</strong>
            <div style="color: #64748b; font-size: 11px; font-family: monospace; margin-top: 4px; word-break: break-all;">{html.escape(json.dumps(details, ensure_ascii=False))}</div>
        </li>
        """
    return f"<ul style='padding-left: 0; margin: 0;'>{items}</ul>"


def chat_and_detect(user_message: str, history: list, threshold: float, role: str):
    global conversation

    if not user_message or not user_message.strip():
        return history, "", "Brak tekstu", TOOLS_PLACEHOLDER, EVENTS_PLACEHOLDER, "{}"

    if conversation is None or conversation.role != role:
        conversation = pipeline.Conversation(role)

    # Cała tura przechodzi przez pipeline: strażnik promptu -> maskowanie -> chatbot z bramką
    # narzędzi -> filtr odpowiedzi -> log audytu.
    result = pipeline.run_turn(conversation, user_message, threshold=threshold)

    guard_status_html = format_guard_verdict_html(result.guard, role)
    masking_html = format_masking_html(result)
    user_status_html = format_entities_html(result.prompt_entities, "Wiadomość Użytkownika")
    model_status_html = format_entities_html(result.output["entities"], "Odpowiedź Modelu Gemma (przed filtrem)")

    history = history or []
    history.append({"role": "user", "content": user_message})
    history.append({"role": "assistant", "content": result.reply})

    combined_status = guard_status_html + masking_html + user_status_html + model_status_html
    tools_html = format_tool_calls_html(role, result.tool_calls)
    raw_json = json.dumps({
        "role": role,
        "blocked": result.blocked,
        "block_reason": result.block_reason,
        "prompt_guard": {
            "decision": result.guard.decision,
            "reason": result.guard.reason,
            "has_warning": result.guard.has_warning,
            "is_blocked": result.guard.is_blocked,
        },
        "masked_prompt": result.masked_prompt,
        "leaks_to_chatbot": result.leaks_to_chatbot,
        "tool_calls": result.tool_calls,
        "events": result.events,
    }, indent=2, ensure_ascii=False)

    return history, "", combined_status, tools_html, format_events_html(result.events), raw_json


def clear_chat():
    global conversation
    conversation = None
    return [], "", "<div style='color: #64748b; padding: 12px;'>Wyczyśćono czat. Czekam na nową wiadomość...</div>", TOOLS_PLACEHOLDER, EVENTS_PLACEHOLDER, "{}"


def change_role(role: str):
    """Zmiana roli czyści rozmowę — historia może zawierać dane pobrane narzędziami poprzedniej roli."""
    return (role_info(role), *clear_chat())


# Budowa interfejsu Gradio
custom_css = """
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
.gradio-container { max-width: 1200px !important; margin: auto !important; }
"""

with gr.Blocks(title="AI Security Layer - PII & Gemma Testbed", theme=gr.themes.Soft(), css=custom_css) as demo:
    gr.Markdown(f"""
    # 🛡️ AI Security Layer — Testbed PII & Gemma (OpenRouter)
    **Chatbot:** `{LLM_PROVIDER}` / `{MODEL}` | **Strefa bezpieczeństwa:** `{SECURITY_PROVIDER or LLM_PROVIDER}` / `{SECURITY_MODEL or MODEL}` | **PII Model:** `{PII_MODEL}`
    **Maskowanie:** `{"włączone" if SETTINGS.mask_pii else "wyłączone"}` | **Sędzia PII:** `{"włączony" if PII_JUDGE_ENABLED else "wyłączony"}`
    *Każda wysłana wiadomość użytkownika oraz wygenerowana odpowiedź przechodzi przez moduł wykrywania danych wrażliwych (GLiNER + Regex).*
    """)

    with gr.Row():
        with gr.Column(scale=7):
            role_dropdown = gr.Dropdown(
                choices=list(ROLES),
                value=DEFAULT_ROLE,
                label="Rola użytkownika (zmiana roli czyści rozmowę)",
            )
            role_panel = gr.Markdown(role_info(DEFAULT_ROLE))
            chatbot = gr.Chatbot(
                label="Rozmowa z Gemma (OpenRouter)",
                type="messages",
                height=520,
            )
            with gr.Row():
                msg_input = gr.Textbox(
                    placeholder="Wpisz wiadomość lub kliknij jeden z gotowych przykładów poniżej...",
                    label="Twoja wiadomość",
                    scale=8,
                    lines=2,
                )
                with gr.Column(scale=2):
                    send_btn = gr.Button("Wyślij 🚀", variant="primary", scale=1)
                    clear_btn = gr.Button("Wyczyść 🗑️", variant="secondary", scale=1)

            gr.Markdown("### 💡 Szybkie testy przypadków wrażliwych (kliknij, aby przetestować natychmiast):")
            examples = gr.Examples(
                examples=[
                    ["I am working on a project SimpleText AI"],
                    ["The password is Admin123"],
                    ["Boss earns 24 000 $"],
                    ["I am moving to USA"],
                    ["She works at Google"],
                    ["Call me at +48 600 700 800"],
                    ["The weather is very nice today"],
                    ["Jakie projekty dotyczące security mamy w bazie wiedzy?"],
                    ["Pokaż 5 pracowników z działu Sales razem z ich miesięcznym wynagrodzeniem"],
                    ["Podaj dane klienta banku o customer_id 15647311"],
                    ["Podaj notowania AAPL z NASDAQ ze stycznia 2024"],
                    ["Wyślij podsumowanie projektów security na jan.kowalski@firma.pl, mój telefon to +48 600 700 800"],
                    ["Co Tim Cook mówił o usługach na telekonferencji Apple za Q1 2024?"],
                ],
                inputs=msg_input,
            )

        with gr.Column(scale=5):
            gr.Markdown("### 🛠️ Narzędzia wywołane przez model (ostatnia odpowiedź)")
            tools_panel = gr.HTML(value=TOOLS_PLACEHOLDER, label="Narzędzia")

            gr.Markdown("### 🚨 Panel Bezpieczeństwa / Detekcji PII (Live)")
            threshold_slider = gr.Slider(
                minimum=0.1,
                maximum=0.9,
                value=0.35,
                step=0.05,
                label="Próg czułości PII (Threshold)",
            )

            status_panel = gr.HTML(
                value="<div style='color: #64748b; padding: 12px; border: 1px dashed #cbd5e1; border-radius: 8px;'>Wyślij pierwszą wiadomość, aby zobaczyć analizę PII w czasie rzeczywistym...</div>",
                label="Status PII",
            )

            with gr.Accordion("Log audytu tury (strefy)", open=True):
                events_panel = gr.HTML(value=EVENTS_PLACEHOLDER, label="Audyt")

            with gr.Accordion("Szczegóły techniczne (JSON)", open=False):
                json_output = gr.Code(
                    value="{}",
                    language="json",
                    label="Wykryte encje (Raw JSON)",
                )

    # Reakcje na akcje
    send_btn.click(
        fn=chat_and_detect,
        inputs=[msg_input, chatbot, threshold_slider, role_dropdown],
        outputs=[chatbot, msg_input, status_panel, tools_panel, events_panel, json_output],
    )

    msg_input.submit(
        fn=chat_and_detect,
        inputs=[msg_input, chatbot, threshold_slider, role_dropdown],
        outputs=[chatbot, msg_input, status_panel, tools_panel, events_panel, json_output],
    )

    clear_btn.click(
        fn=clear_chat,
        inputs=[],
        outputs=[chatbot, msg_input, status_panel, tools_panel, events_panel, json_output],
    )

    role_dropdown.change(
        fn=change_role,
        inputs=[role_dropdown],
        outputs=[role_panel, chatbot, msg_input, status_panel, tools_panel, events_panel, json_output],
    )


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  Uruchamianie interfejsu testowego Gradio...")
    print(f"  Model LLM: {MODEL} via {LLM_PROVIDER}")
    print(f"  Model PII: {PII_MODEL}")
    print("=" * 60 + "\n")
    demo.launch(server_name="127.0.0.1", share=False)

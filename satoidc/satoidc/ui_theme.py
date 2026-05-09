from nicegui import ui


def apply_theme() -> None:
    ui.colors(
        primary="#3874C8",
        secondary="#F59E0B",
        accent="#38BDF8",
        dark="#070B16",
        dark_page="#070B16",
        positive="#16A34A",
        negative="#DC2626",
        warning="#F59E0B",
        info="#38BDF8",
    )

    ui.button.default_props("unelevated no-caps")
    ui.button.default_classes(
        "rounded-lg px-4 py-2 font-medium transition-all duration-200 "
        "text-slate-800 dark:text-slate-100 hover:-translate-y-0.5 "
        "focus-visible:ring-2 focus-visible:ring-sky-400/40"
    )
    field_classes = (
        "w-full rounded-xl bg-white/70 dark:bg-slate-900/70 border "
        "border-slate-200/80 dark:border-white/10 text-slate-950 "
        "dark:text-slate-50 placeholder:text-slate-500 "
        "dark:placeholder:text-slate-500 focus-within:ring-2 "
        "focus-within:ring-sky-400/35 transition-all duration-200 "
        "shadow-sm shadow-slate-200/40 dark:shadow-none"
    )
    ui.input.default_props("outlined dense color=info")
    ui.input.default_classes(field_classes)
    ui.textarea.default_props("outlined dense color=info")
    ui.textarea.default_classes(field_classes)
    ui.select.default_props("outlined dense color=info")
    ui.select.default_classes(field_classes)
    ui.card.default_classes(
        "rounded-2xl border border-slate-200/70 dark:border-white/10 "
        "bg-white/75 dark:bg-slate-900/80 text-slate-950 "
        "dark:text-slate-50 backdrop-blur-xl shadow-xl "
        "shadow-slate-200/60 dark:shadow-black/20"
    )
    ui.table.default_classes(
        "overflow-hidden rounded-2xl border border-slate-200/70 "
        "dark:border-white/10 bg-white/75 dark:bg-slate-900/80 "
        "text-slate-950 dark:text-slate-50 shadow-xl "
        "shadow-slate-200/50 dark:shadow-black/20 backdrop-blur-xl"
    )

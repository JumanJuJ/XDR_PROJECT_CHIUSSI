window.dashCharts = (function() {
    function ensureChartJs()
    {
        if (!window.Chart) throw new Error("Chart.js non caricato");
    }

    function renderKindChart(canvasId, items)
    {
        ensureChartJs();
        const el = document.getElementById(canvasId);
        if (!el) return;

        const labels = items.map(x => x.label);
        const values = items.map(x => x.value);

        if (el._chart) el._chart.destroy();

        el._chart = new Chart(el, {
            type: "bar",
            data:
    {
        labels,
                datasets: [{ data: values }]
            },
            options:
    {
    responsive: true,
                plugins: { legend: { display: false } },
                scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }
    }
});
    }

    function renderTrendChart(canvasId, points)
{
    ensureChartJs();
    const el = document.getElementById(canvasId);
    if (!el) return;

    const labels = points.map(x => x.label);
    const values = points.map(x => x.value);

    if (el._chart) el._chart.destroy();

    el._chart = new Chart(el, {
            type: "line",
            data:
{
    labels,
                datasets: [{ data: values, tension: 0.2, pointRadius: 2 }]
            },
            options:
{
responsive: true,
                plugins: { legend: { display: false } },
                scales:
    {
    y: { beginAtZero: true, ticks: { precision: 0 }, suggestedMax: 2 }
    }
}
        });
    }

    return { renderKindChart, renderTrendChart }
;
})();

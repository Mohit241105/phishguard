/**
 * Chart.js Visualizations for PhishGuard AI Dashboard & Results
 */
let barChartInstance = null;
let doughnutChartInstance = null;
let radialChartInstance = null;
let drawerScoreChartInstance = null;

function initCharts() {
    // 1. Top Bar Chart: Historical Scan Stats
    const barCtx = document.getElementById('barChart');
    if (barCtx) {
        barChartInstance = new Chart(barCtx, {
            type: 'bar',
            data: {
                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
                datasets: [
                    {
                        label: 'Safe Emails',
                        data: [35, 28, 42, 38, 45, 50, 48, 55, 60, 52, 58, 65],
                        backgroundColor: '#00e676',
                        borderRadius: 4
                    },
                    {
                        label: 'Suspicious',
                        data: [15, 12, 18, 14, 20, 16, 22, 19, 25, 21, 24, 28],
                        backgroundColor: '#ffb300',
                        borderRadius: 4
                    },
                    {
                        label: 'Phishing Attacks',
                        data: [8, 14, 10, 16, 12, 22, 18, 26, 20, 30, 25, 32],
                        backgroundColor: '#ff5252',
                        borderRadius: 4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: '#8a99ad', font: { size: 10 } }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#8a99ad', font: { size: 10 } }
                    }
                }
            }
        });
    }

    // 2. Bottom Left Doughnut Chart
    const doughnutCtx = document.getElementById('doughnutChart');
    if (doughnutCtx) {
        doughnutChartInstance = new Chart(doughnutCtx, {
            type: 'doughnut',
            data: {
                labels: ['Safe Ratio', 'Phishing Ratio'],
                datasets: [{
                    data: [80, 20],
                    backgroundColor: ['#00e676', '#ff5252'],
                    borderWidth: 0,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '78%',
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    // 3. Bottom Right Radial Multi-Ring Gauge
    const radialCtx = document.getElementById('radialChart');
    if (radialCtx) {
        radialChartInstance = new Chart(radialCtx, {
            type: 'doughnut',
            data: {
                labels: ['Header Integrity', 'URL Security', 'NLP Social Eng'],
                datasets: [{
                    data: [60, 40],
                    backgroundColor: ['#00f2fe', 'rgba(255,255,255,0.05)'],
                    borderWidth: 0,
                    cutout: '85%'
                }, {
                    data: [78, 22],
                    backgroundColor: ['#4facfe', 'rgba(255,255,255,0.05)'],
                    borderWidth: 0,
                    cutout: '70%'
                }, {
                    data: [76, 24],
                    backgroundColor: ['#7f00ff', 'rgba(255,255,255,0.05)'],
                    borderWidth: 0,
                    cutout: '55%'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    // 4. Drawer Score Chart inside Results Drawer
    const drawerCtx = document.getElementById('drawerScoreChart');
    if (drawerCtx) {
        drawerScoreChartInstance = new Chart(drawerCtx, {
            type: 'bar',
            data: {
                labels: ['Header Risk', 'URL Risk', 'Attachment Risk', 'NLP Tactic', 'AI ML Score'],
                datasets: [{
                    label: 'Risk Points (0-100)',
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: ['#00f2fe', '#4facfe', '#7f00ff', '#ffb300', '#ff5252'],
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y', // Horizontal Bar Chart
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        min: 0,
                        max: 100,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#8a99ad', font: { size: 10 } }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: '#ffffff', font: { size: 11, weight: 'bold' } }
                    }
                }
            }
        });
    }
}

function updateChartsWithReport(report) {
    const scores = report.scores || {};
    const finalScore = report.final_risk_score || 0;

    // Update center title
    const centerTitle = document.getElementById('center-score-val');
    if (centerTitle) {
        centerTitle.innerText = `${finalScore} / 100`;
        if (report.verdict === 'PHISHING') {
            centerTitle.style.color = '#ff5252';
        } else if (report.verdict === 'SUSPICIOUS') {
            centerTitle.style.color = '#ffb300';
        } else {
            centerTitle.style.color = '#00e676';
        }
    }

    // Update Radial Multi-Ring Gauge
    const hScore = scores.header_score || 0;
    const uScore = scores.url_score || 0;
    const nScore = scores.nlp_score || 0;

    const gHeader = document.getElementById('gauge-header-val');
    const gUrl = document.getElementById('gauge-url-val');
    const gNlp = document.getElementById('gauge-nlp-val');

    if (gHeader) gHeader.innerText = `Header: ${hScore}%`;
    if (gUrl) gUrl.innerText = `URL: ${uScore}%`;
    if (gNlp) gNlp.innerText = `NLP: ${nScore}%`;

    if (radialChartInstance) {
        radialChartInstance.data.datasets[0].data = [hScore, 100 - hScore];
        radialChartInstance.data.datasets[1].data = [uScore, 100 - uScore];
        radialChartInstance.data.datasets[2].data = [nScore, 100 - nScore];
        radialChartInstance.update();
    }

    // Update Drawer Score Chart
    if (drawerScoreChartInstance) {
        drawerScoreChartInstance.data.datasets[0].data = [
            hScore,
            uScore,
            scores.attachment_score || 0,
            nScore,
            scores.ml_score || 0
        ];
        drawerScoreChartInstance.update();
    }
}

document.addEventListener('DOMContentLoaded', initCharts);

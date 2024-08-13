'use strict';
document.addEventListener("DOMContentLoaded", function () {
    setTimeout(function() {
        floatchart()
    }, 100);
    // [ campaign-scroll ] start
    var px = new PerfectScrollbar('.customer-scroll', {
        wheelSpeed: .5,
        swipeEasing: 0,
        wheelPropagation: 1,
        minScrollbarLength: 40,
    });
    var px = new PerfectScrollbar('.customer-scroll1', {
        wheelSpeed: .5,
        swipeEasing: 0,
        wheelPropagation: 1,
        minScrollbarLength: 40,
    });
    var px = new PerfectScrollbar('.customer-scroll2', {
        wheelSpeed: .5,
        swipeEasing: 0,
        wheelPropagation: 1,
        minScrollbarLength: 40,
    });
    var px = new PerfectScrollbar('.customer-scroll3', {
        wheelSpeed: .5,
        swipeEasing: 0,
        wheelPropagation: 1,
        minScrollbarLength: 40,
    });
    // [ campaign-scroll ] end
});

function floatchart() {

    // [ coversions-chart ] start
    (function () {
        var options1 = {
            chart: {
                type: 'bar',
                height: 65,
                sparkline: {
                    enabled: true
                }
            },
            dataLabels: {
                enabled: false
            },
            colors: ["#73b4ff"],
            fill: {
                type: 'gradient',
                gradient: {
                    shade: 'light',
                    type: "vertical",
                    shadeIntensity: 0,
                    gradientToColors: ["#4099ff"],
                    inverseColors: true,
                    opacityFrom: 0.99,
                    opacityTo: 0.99,
                    stops: [0, 100]
                },
            },
            plotOptions: {
                bar: {
                    columnWidth: '80%'
                }
            },
            series: [{
                data: [25, 66, 41, 89, 63, 25, 44, 12, 36, 9, 54, 25, 66, 41, 89, 63, 54, 25, 66, 41, 85, 63, 25, 44, 12, 36, 9, 54, 25, 66, 41, 89, 63, 25, 44, 12, 36, 9, 25, 44, 12, 36, 9, 54]
            }],
            xaxis: {
                crosshairs: {
                    width: 1
                },
            },
            tooltip: {
                fixed: {
                    enabled: false
                },
                x: {
                    show: false
                },
                y: {
                    title: {
                        formatter: function(seriesName) {
                            return ''
                        }
                    }
                },
                marker: {
                    show: false
                }
            }
        }
        new ApexCharts(document.querySelector("#coversions-chart1"), options1).render();
        var options2 = {
            chart: {
                type: 'bar',
                height: 65,
                sparkline: {
                    enabled: true
                }
            },
            dataLabels: {
                enabled: false
            },
            colors: ["#59e0c5"],
            fill: {
                type: 'gradient',
                gradient: {
                    shade: 'light',
                    type: "vertical",
                    shadeIntensity: 0,
                    gradientToColors: ["#2ed8b6"],
                    inverseColors: true,
                    opacityFrom: 0.99,
                    opacityTo: 0.99,
                    stops: [0, 100]
                },
            },
            plotOptions: {
                bar: {
                    columnWidth: '80%'
                }
            },
            series: [{
                data: [25, 66, 41, 89, 63, 25, 44, 12, 36, 9, 54, 25, 66, 41, 89, 63, 54, 25, 66, 41, 85, 63, 25, 44, 12, 36, 9, 54, 25, 66, 41, 89, 63, 25, 44, 12, 36, 9, 25, 44, 12, 36, 9, 54]
            }],
            xaxis: {
                crosshairs: {
                    width: 1
                },
            },
            tooltip: {
                fixed: {
                    enabled: false
                },
                x: {
                    show: false
                },
                y: {
                    title: {
                        formatter: function(seriesName) {
                            return ''
                        }
                    }
                },
                marker: {
                    show: false
                }
            }
        }
        new ApexCharts(document.querySelector("#coversions-chart2"), options2).render();
        var options4 = {
            chart: {
                type: 'bar',
                height: 65,
                sparkline: {
                    enabled: true
                }
            },
            dataLabels: {
                enabled: false
            },
            colors: ["#ff869a"],
            fill: {
                type: 'gradient',
                gradient: {
                    shade: 'light',
                    type: "vertical",
                    shadeIntensity: 0,
                    gradientToColors: ["#ff5370"],
                    inverseColors: true,
                    opacityFrom: 0.99,
                    opacityTo: 0.99,
                    stops: [0, 100]
                },
            },
            plotOptions: {
                bar: {
                    columnWidth: '80%'
                }
            },
            series: [{
                data: [25, 66, 41, 89, 63, 25, 44, 12, 36, 9, 54, 25, 66, 41, 89, 63, 54, 25, 66, 41, 85, 63, 25, 44, 12, 36, 9, 54, 25, 66, 41, 89, 63, 25, 44, 12, 36, 9, 25, 44, 12, 36, 9, 54]
            }],
            xaxis: {
                crosshairs: {
                    width: 1
                },
            },
            tooltip: {
                fixed: {
                    enabled: false
                },
                x: {
                    show: false
                },
                y: {
                    title: {
                        formatter: function(seriesName) {
                            return ''
                        }
                    }
                },
                marker: {
                    show: false
                }
            }
        }
        new ApexCharts(document.querySelector("#coversions-chart4"), options4).render();
    })();
    // [ coversions-chart ] end
    // [ seo-card1 ] start
    (function () {
        var options1 = {
            chart: {
                type: 'area',
                height: 145,
                sparkline: {
                    enabled: true
                }
            },
            dataLabels: {
                enabled: false
            },
            colors: ["#ff5370"],
            fill: {
                type: 'gradient',
                gradient: {
                    shade: 'dark',
                    gradientToColors: ['#ff869a'],
                    shadeIntensity: 1,
                    type: 'horizontal',
                    opacityFrom: 1,
                    opacityTo: 0.8,
                    stops: [0, 100, 100, 100]
                },
            },
            stroke: {
                curve: 'smooth',
                width: 2,
            },
            series: [{
                data: [45, 35, 60, 50, 85, 70]
            }],
            yaxis: {
               min: 5,
               max: 90,
           },
            tooltip: {
                fixed: {
                    enabled: false
                },
                x: {
                    show: false
                },
                y: {
                    title: {
                        formatter: function(seriesName) {
                            return 'Ticket '
                        }
                    }
                },
                marker: {
                    show: false
                }
            }
        }
        new ApexCharts(document.querySelector("#seo-card1"), options1).render();
    })();
    // [ seo-card1 ] end
    // [ customer-chart ] start
    (function () {
        var options = {
            chart: {
                height: 150,
                type: 'donut',
            },
            dataLabels: {
                enabled: false
            },
            plotOptions: {
                pie: {
                    donut: {
                        size: '75%'
                    }
                }
            },
            labels: ['New', 'Return'],
            series: [39, 10],
            legend: {
                show: false
            },
            tooltip: {
                theme: 'datk'
            },
            grid: {
                padding: {
                    top: 20,
                    right: 0,
                    bottom: 0,
                    left: 0
                },
            },
            colors: ["#4680ff", "#2ed8b6"],
            fill: {
                opacity: [1, 1]
            },
            stroke: {
                width: 0,
            }
        }
        var chart = new ApexCharts(document.querySelector("#customer-chart"), options);
        chart.render();
        var options1 = {
            chart: {
                height: 150,
                type: 'donut',
            },
            dataLabels: {
                enabled: false
            },
            plotOptions: {
                pie: {
                    donut: {
                        size: '75%'
                    }
                }
            },
            labels: ['New', 'Return'],
            series: [20, 15],
            legend: {
                show: false
            },
            tooltip: {
                theme: 'dark'
            },
            grid: {
                padding: {
                    top: 20,
                    right: 0,
                    bottom: 0,
                    left: 0
                },
            },
            colors: ["#fff", "#2ed8b6"],
            fill: {
                opacity: [1, 1]
            },
            stroke: {
                width: 0,
            }
        }
        var chart = new ApexCharts(document.querySelector("#customer-chart1"), options1);
        chart.render();
    })();
    // [ customer-chart ] end
    // [ unique-visitor-chart ] start
    (function () {
        var options = {
            chart: {
                height: 230,
                type: 'line',
                toolbar: {
                    show: false,
                },
            },
            dataLabels: {
                enabled: false
            },
            stroke: {
                width: 2,
                curve: 'smooth'
            },
            series: [{
                name: 'Arts',
                data: [20, 50, 30, 60, 30, 50]
            }, {
                name: 'Commerce',
                data: [60, 30, 65, 45, 67, 35]
            }],
            legend: {
                position: 'top',
            },
            xaxis: {
                type: 'datetime',
                categories: ['1/11/2000', '2/11/2000', '3/11/2000', '4/11/2000', '5/11/2000', '6/11/2000'],
                axisBorder: {
                    show: false,
                },
                label: {
                    style: {
                        color: '#ccc'
                    }
                },
            },
            yaxis: {
                show: true,
                min: 10,
                max: 70,
                labels: {
                    style: {
                        color: '#ccc'
                    }
                }
            },
            colors: ['#73b4ff', '#59e0c5'],
            fill: {
                type: 'gradient',
                gradient: {
                    shade: 'light',
                    gradientToColors: ['#4099ff', '#2ed8b6'],
                    shadeIntensity: 0.5,
                    type: 'horizontal',
                    opacityFrom: 1,
                    opacityTo: 1,
                    stops: [0, 100]
                },
            },
            markers: {
                size: 5,
                colors: ['#4099ff', '#2ed8b6'],
                opacity: 0.9,
                strokeWidth: 2,
                hover: {
                    size: 7,
                }
            },
            grid: {
                borderColor: '#cccccc3b',
            }
        }
        var chart = new ApexCharts(document.querySelector("#unique-visitor-chart"), options);
        chart.render();
    })();
    // [ unique-visitor-chart ] end
}
$(document).ready(function() {
    $('#loading').show();
    $('#vulns').hide();
    $('#domain').hide();
    $('#result').hide();
    $('#pie-chart-1').hide();
    $('#IP').hide();
    $('#urls').hide();
    $('#vuln-chart').hide();
    $('#table').hide();
    $('#linkedinForm').submit(function(event) {
            event.preventDefault(); // Previene il submit di default del form
            var url = $('#linkedinUrl').val();
            var domain = window.domain;
            $('#loading-linkedin').show();
            $.ajax({
                url: "/linkedinDump",
                type: "GET",
                data: { url: url, domain: domain},
                success: function(response) {
                    $('#loading-linkedin').hide();
                    $('#result').show();
                    document.getElementById('worker-count').textContent = response.linkedinDump.length;
                    if (response.linkedinDump.length > 0) {
                        $('#download-workers-btn').show();
                        document.getElementById('download-workers-btn').onclick = function() {
                            downloadJson("Workers",response.linkedinDump);
                        };
                        $('#download-email-btn').show();
                        document.getElementById('download-email-btn').onclick = function() {
                            downloadJson("Guessable-Emails",response.guessable_emails);
                        };
                        $('#download-verified-email-btn').show();
                        document.getElementById('download-verified-email-btn').onclick = function() {
                            downloadJson("Verified-Emails",response.verified_emails);
                        };
                    }
                },
                error: function(error) {
                    console.error(error);
                    $('#result').html('<p>Si è verificato un errore durante la richiesta.</p>');
                }
            });
        });
    function checkTheHarvesterStatus() {
        var domain = window.domain;
        $.ajax({
            url: "/theharvester_status",
            type: "GET",
            data: { domain: domain },
            success: function(data) {
                if (data.status === "processing") {
                    setTimeout(checkTheHarvesterStatus, 5000);
                } else {
                    var IP = data.IP;
                    var urls = data.interesting_urls;
                    document.getElementById('total-domain').textContent = data.numDomini;;
                    document.getElementById('resolved-domain').textContent = data.numResolvedHosts;
                    document.getElementById('total-ip').textContent = data.numIP;
                    document.getElementById('total-urls').textContent = data.numUrls;
                    $('#domain').show();
                    $('#IP').show();
                    $('#urls').show();

                    if (data.domini.length > 0) {
                        $('#download-domain-btn').show();
                        document.getElementById('download-domain-btn').onclick = function() {
                            downloadJson("Domains",data.domini);
                        };
                    }

                    if (Object.keys(data.resolved_hosts).length > 0) {
                        $('#download-resolved-domain-btn').show();
                        document.getElementById('download-resolved-domain-btn').onclick = function() {
                            downloadJson("Resolved_domains",data.resolved_hosts);
                        };
                    }

                    if (IP.length > 0) {
                        $('#download-ip-btn').show();
                        document.getElementById('download-ip-btn').onclick = function() {
                            downloadJson("IP",IP);
                        };
                    }

                    if (urls.length > 0) {
                        $('#download-urls-btn').show();
                        document.getElementById('download-urls-btn').onclick = function() {
                            downloadJson("URLs",urls);
                        };
                    }
                    $('#download-all-btn').show();
                        document.getElementById('download-all-btn').onclick = function() {
                            downloadJson("Full_Json",data);
                        };

                    shodan(IP,urls);
                    
                }
            },
            error: function(jqXHR, textStatus, errorThrown) {
    console.error("Errore durante la richiesta AJAX:", textStatus, errorThrown);
}
        });
    }

    function downloadJson(key,json) {
        const data = JSON.stringify({ [key]: json }, null, 2);
        const blob = new Blob([data], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${key}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    function populateTable(jsonResponse) {
// Trova il corpo della tabella
let tableBody = document.getElementById('table-body');
tableBody.innerHTML = ''; // Resetta il contenuto della tabella

// Itera sui dati JSON e crea le righe della tabella
jsonResponse.forEach(item => {
    let row = document.createElement('tr');

    if (item.criticalVulns > 0 || item.highVulns > 0) {
        row.className = 'table-danger';
    }
    else if (item.mediumVulns > 0) {
        row.className = 'table-warning';
    }

    else row.className = 'table-success';

    // Colonna per l'indirizzo IP
    let ipCell = document.createElement('td');
    ipCell.textContent = item.ip;
    row.appendChild(ipCell);

    // Colonna per Critical Vulnerabilities
    let criticalCell = document.createElement('td');
    criticalCell.textContent = item.criticalVulns;
    row.appendChild(criticalCell);

    // Colonna per High Vulnerabilities
    let highCell = document.createElement('td');
    highCell.textContent = item.highVulns;
    row.appendChild(highCell);

    // Colonna per Medium Vulnerabilities
    let mediumCell = document.createElement('td');
    mediumCell.textContent = item.mediumVulns;
    row.appendChild(mediumCell);

    // Colonna per Low Vulnerabilities
    let lowCell = document.createElement('td');
    lowCell.textContent = item.lowVulns;
    row.appendChild(lowCell);

    // Aggiungi la riga alla tabella
    tableBody.appendChild(row);
});
}
    function updateInfo(jsonResponse) {
        let totalVulns = jsonResponse.total_vulns;
        let mostCriticalIP = '';
        let maxVulns = 0;
        // Trova l'IP con il numero massimo di vulnerabilità
        jsonResponse.results.forEach(result => {
            let ipVulns = result.criticalVulns + result.highVulns + result.mediumVulns + result.lowVulns;
            if (ipVulns > maxVulns) {
                maxVulns = ipVulns;
                mostCriticalIP = result.ip;
        }
    });

        // Aggiorna il DOM
        document.getElementById('total-vulns').textContent = totalVulns;
        document.getElementById('most-critical-ip').textContent = mostCriticalIP;

    var options = {
        chart: {
            height: 320,
            type: 'pie',
        },
        labels:  ["Critical", "High", "Medium", "Low"],
        series: [
    jsonResponse.total_critical_vulns,
    jsonResponse.total_high_vulns,
    jsonResponse.total_medium_vulns,
    jsonResponse.total_low_vulns
    ],
        colors:  ["#800080", "#FF0000", "#FFA500", "#228B22"],
        legend: {
            show: true,
            position: 'bottom',
        },
        fill: {
            type: 'gradient',
            gradient: {
                shade: 'light',
                inverseColors: true,
            }
        },
        dataLabels: {
            enabled: true,
            dropShadow: {
                enabled: false,
            }
        },
        responsive: [{
            breakpoint: 480,
            options: {
                legend: {
                    position: 'bottom'
                }
            }
        }]
    };
    var chart = new ApexCharts(
        document.querySelector("#pie-chart-1"),
        options
    );
    chart.render();
}
    function shodan(IP,urls) {
        $.ajax({
            url: "/search_shodan",
            method: "GET",
            data: { json: JSON.stringify({ IP: IP, urls: urls }) },
            success: function(data) {
                $('#loading').hide();
                $('#vulns').show();
                $('#vuln-chart').show();
                $('#pie-chart-1').show();
                $('#table').show();
                
                if (data.results.length > 0) {
                    $('#download-vuln-btn').show();
                    document.getElementById('download-vuln-btn').onclick = function() {
                        downloadJson("Vulnerabilities",data);
                    };
                }
                updateInfo(data);
                populateTable(data.results);
            },
            error: function(jqXHR, textStatus, errorThrown) {
                console.error("Errore durante la richiesta AJAX:", textStatus, errorThrown);
            }
        });
    }

    checkTheHarvesterStatus();
});
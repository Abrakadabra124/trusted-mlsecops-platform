# Client admission: native failure f273fd5

[Storage CI](https://github.com/Abrakadabra124/trusted-mlsecops-platform/actions/runs/38785840394), job `116597499086`, code `f273fd533bd4d1644ecc8dffadb89d6be145f8cf`. Отчёт не исправлен задним числом. Полный actual-candidate runner не завершился: HTTP trust-outage assessment fail, последующие paused/expiry/revoke/source-preservation checks не подтверждены этим прогоном.

Quota checks до outage прошли, но старый диагностический опрос каждые 5 ms около lease deadline исчерпал новый client budget 20/s, burst 40. В сохранённом trace: 88 ответов 200, 15 ответов 429 и 41 ответ 503. Первый 503 получен за 59.742117598 s, но 429 недопустим в этом опыте, поэтому timely denial сам по себе не даёт pass. Recovery проверен внутри outage helper; это не подтверждает все последующие cleanup checks общего runner.

Correction ограничивает частоту самого опроса: пауза не менее 50 ms после ответа около deadline. Auth, client quotas, production response deadline, порог 60 s и запрет считать 429 допустимым outage response не изменены. Regression использует настоящий Access с controlled clock и воспроизводит прежний отказ до исправления. [Основное evidence](serving-clients-2026-10-15.md).

## Сохранённый sanitized trace

```json
{
  "assessment": {
    "failures": [
      "http_response_invalid",
      "unexpected_http_status"
    ],
    "first_503_seconds": 59.74211759799999,
    "last_200_seconds": 59.704369042999986,
    "observations": 144,
    "release_ready": false,
    "scope": "http-trust-outage-component-not-full-M11",
    "status": "fail"
  },
  "identity": {
    "bundle_sha256": "6f6d4c1b88c9e59640e19ea72a17ae5f457380aeb694e2653c3cf18852a29919",
    "model_sha256": "09c48030c2a98d78d74d0a31d4fe18b081e4906abadf5be8a246ec4faa416b8f"
  },
  "last_verified": {
    "deadline": 502.141886122,
    "document_sha256": "9f6db13deca7e5dbcc48ec6ac8713c2cd08af575c344f15118621233bd2c27d9",
    "monotonic": 442.153150584,
    "sequence": 28,
    "version": 1,
    "wall": 1792089296.1642141
  },
  "records": [
    {
      "finished_monotonic": 442.585730063,
      "finished_wall": 1792089296.5967941,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 442.574909598,
      "started_wall": 1792089296.5859733,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 444.5964002,
      "finished_wall": 1792089298.607464,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 444.585895123,
      "started_wall": 1792089298.5969586,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 446.607797788,
      "finished_wall": 1792089300.618862,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 446.596590575,
      "started_wall": 1792089300.607654,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 448.619150232,
      "finished_wall": 1792089302.6302142,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 448.607956123,
      "started_wall": 1792089302.6190197,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 450.629866613,
      "finished_wall": 1792089304.6409307,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 450.619300111,
      "started_wall": 1792089304.6303637,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 452.641049465,
      "finished_wall": 1792089306.6521134,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 452.63002024,
      "started_wall": 1792089306.641084,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 454.652632157,
      "finished_wall": 1792089308.663696,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 454.641204644,
      "started_wall": 1792089308.6522682,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 456.662921732,
      "finished_wall": 1792089310.6739855,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 456.652780131,
      "started_wall": 1792089310.6638436,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 458.674236324,
      "finished_wall": 1792089312.6853,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 458.663086738,
      "started_wall": 1792089312.6741505,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 460.686153977,
      "finished_wall": 1792089314.6972177,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 460.674426676,
      "started_wall": 1792089314.6854901,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 462.69723196,
      "finished_wall": 1792089316.7082958,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 462.686315728,
      "started_wall": 1792089316.6973794,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 464.707753762,
      "finished_wall": 1792089318.7188177,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 464.697421617,
      "started_wall": 1792089318.7084851,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 466.719178322,
      "finished_wall": 1792089320.7302423,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 466.707927166,
      "started_wall": 1792089320.7189906,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 468.729948584,
      "finished_wall": 1792089322.7410128,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 468.71936992,
      "started_wall": 1792089322.7304335,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 470.740414691,
      "finished_wall": 1792089324.7514784,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 470.730126778,
      "started_wall": 1792089324.7411904,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 472.751175512,
      "finished_wall": 1792089326.7622395,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 472.740574407,
      "started_wall": 1792089326.751638,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 474.762231837,
      "finished_wall": 1792089328.7732959,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 474.751343677,
      "started_wall": 1792089328.762407,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 476.772975728,
      "finished_wall": 1792089330.7840397,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 476.762380594,
      "started_wall": 1792089330.7734442,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 478.783483701,
      "finished_wall": 1792089332.7945478,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 478.773116059,
      "started_wall": 1792089332.7841797,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 480.794580071,
      "finished_wall": 1792089334.805644,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 480.783672365,
      "started_wall": 1792089334.794736,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 482.805705611,
      "finished_wall": 1792089336.8167698,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 482.794764502,
      "started_wall": 1792089336.805828,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 484.817477437,
      "finished_wall": 1792089338.8285415,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 484.805888192,
      "started_wall": 1792089338.8169518,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 486.828827101,
      "finished_wall": 1792089340.8398912,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 486.817653982,
      "started_wall": 1792089340.8287175,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 488.840534784,
      "finished_wall": 1792089342.8515987,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 488.828998781,
      "started_wall": 1792089342.8400621,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 490.85109169,
      "finished_wall": 1792089344.8621557,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 490.840701971,
      "started_wall": 1792089344.8517654,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 492.862047035,
      "finished_wall": 1792089346.873111,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 492.851280153,
      "started_wall": 1792089346.8623438,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 494.872676527,
      "finished_wall": 1792089348.8837404,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 494.862197638,
      "started_wall": 1792089348.873261,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 496.883746557,
      "finished_wall": 1792089350.8948104,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 496.872836777,
      "started_wall": 1792089350.8839004,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 498.894667454,
      "finished_wall": 1792089352.9057314,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 498.883930756,
      "started_wall": 1792089352.8949943,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 500.906414013,
      "finished_wall": 1792089354.917478,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 500.894858692,
      "started_wall": 1792089354.9059224,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 500.92260496,
      "finished_wall": 1792089354.9336689,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 500.911512831,
      "started_wall": 1792089354.9225764,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 500.937778653,
      "finished_wall": 1792089354.9488425,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 500.927700973,
      "started_wall": 1792089354.9387646,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 500.95260571,
      "finished_wall": 1792089354.9636695,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 500.942868844,
      "started_wall": 1792089354.9539325,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 500.967525591,
      "finished_wall": 1792089354.9785895,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 500.957696352,
      "started_wall": 1792089354.96876,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 500.983328035,
      "finished_wall": 1792089354.9943922,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 500.972621924,
      "started_wall": 1792089354.9836855,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 500.998597747,
      "finished_wall": 1792089355.0096617,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 500.988421362,
      "started_wall": 1792089354.999485,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.013903296,
      "finished_wall": 1792089355.0249674,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.003691825,
      "started_wall": 1792089355.0147552,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.030001129,
      "finished_wall": 1792089355.0410652,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.018997364,
      "started_wall": 1792089355.030061,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.046221069,
      "finished_wall": 1792089355.0572848,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.035122989,
      "started_wall": 1792089355.0461864,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.061793064,
      "finished_wall": 1792089355.0728571,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.051318574,
      "started_wall": 1792089355.062382,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.07763983,
      "finished_wall": 1792089355.088704,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.066890669,
      "started_wall": 1792089355.0779543,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.093168595,
      "finished_wall": 1792089355.1042328,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.082735041,
      "started_wall": 1792089355.0937986,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.108572708,
      "finished_wall": 1792089355.1196365,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.098259166,
      "started_wall": 1792089355.1093228,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.123087624,
      "finished_wall": 1792089355.1341515,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.113661317,
      "started_wall": 1792089355.124725,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.137526661,
      "finished_wall": 1792089355.1485906,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.128173007,
      "started_wall": 1792089355.1392367,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.152288077,
      "finished_wall": 1792089355.163352,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.142614548,
      "started_wall": 1792089355.1536782,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.16724638,
      "finished_wall": 1792089355.1783102,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.157380463,
      "started_wall": 1792089355.1684442,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.181768261,
      "finished_wall": 1792089355.192832,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.17233563,
      "started_wall": 1792089355.1833992,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.19623009,
      "finished_wall": 1792089355.207294,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.186861408,
      "started_wall": 1792089355.1979249,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.211623984,
      "finished_wall": 1792089355.222688,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.201319199,
      "started_wall": 1792089355.2123828,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.227204103,
      "finished_wall": 1792089355.238268,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.216716389,
      "started_wall": 1792089355.22778,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.242396722,
      "finished_wall": 1792089355.2534604,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.232292251,
      "started_wall": 1792089355.243356,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.25683674,
      "finished_wall": 1792089355.2679007,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.247481904,
      "started_wall": 1792089355.2585454,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.271278352,
      "finished_wall": 1792089355.2823422,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.261923736,
      "started_wall": 1792089355.2729874,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.285974216,
      "finished_wall": 1792089355.297038,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.276365197,
      "started_wall": 1792089355.2874289,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.30021802,
      "finished_wall": 1792089355.311282,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.291026407,
      "started_wall": 1792089355.30209,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.315367098,
      "finished_wall": 1792089355.326431,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.305306057,
      "started_wall": 1792089355.3163698,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.329961393,
      "finished_wall": 1792089355.3410254,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.320458692,
      "started_wall": 1792089355.3315222,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.345132061,
      "finished_wall": 1792089355.3561962,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.335028672,
      "started_wall": 1792089355.3460922,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.360145657,
      "finished_wall": 1792089355.3712094,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.35023181,
      "started_wall": 1792089355.3612955,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.375541534,
      "finished_wall": 1792089355.3866053,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.365239675,
      "started_wall": 1792089355.3763034,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.391552766,
      "finished_wall": 1792089355.4026167,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.380649638,
      "started_wall": 1792089355.3917134,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.40777505,
      "finished_wall": 1792089355.418839,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.396652685,
      "started_wall": 1792089355.407716,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.423719758,
      "finished_wall": 1792089355.4347837,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.412871954,
      "started_wall": 1792089355.4239354,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.439364198,
      "finished_wall": 1792089355.4504282,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.428835798,
      "started_wall": 1792089355.4398994,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.45464972,
      "finished_wall": 1792089355.4657137,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.44446563,
      "started_wall": 1792089355.4555292,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.469791404,
      "finished_wall": 1792089355.4808552,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.459743037,
      "started_wall": 1792089355.4708066,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.484657274,
      "finished_wall": 1792089355.495721,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.474886825,
      "started_wall": 1792089355.4859505,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.499203971,
      "finished_wall": 1792089355.510268,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.489748638,
      "started_wall": 1792089355.5008123,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.514630756,
      "finished_wall": 1792089355.5256946,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.504290746,
      "started_wall": 1792089355.5153544,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.529425354,
      "finished_wall": 1792089355.5404892,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.519722109,
      "started_wall": 1792089355.5307858,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.544828264,
      "finished_wall": 1792089355.555892,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.534512129,
      "started_wall": 1792089355.5455756,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.559669529,
      "finished_wall": 1792089355.5707333,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.549916712,
      "started_wall": 1792089355.5609803,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.575726726,
      "finished_wall": 1792089355.5867906,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.564760893,
      "started_wall": 1792089355.5758245,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.591483996,
      "finished_wall": 1792089355.602548,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.580817349,
      "started_wall": 1792089355.591881,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.606828798,
      "finished_wall": 1792089355.617893,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.596572164,
      "started_wall": 1792089355.6076357,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.622115301,
      "finished_wall": 1792089355.6331792,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.611918899,
      "started_wall": 1792089355.6229825,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.637293353,
      "finished_wall": 1792089355.6483572,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.62720956,
      "started_wall": 1792089355.6382732,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.653505639,
      "finished_wall": 1792089355.6645696,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.642383725,
      "started_wall": 1792089355.6534474,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.669052638,
      "finished_wall": 1792089355.6801164,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.658602794,
      "started_wall": 1792089355.6696663,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.684598764,
      "finished_wall": 1792089355.6956625,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.674155773,
      "started_wall": 1792089355.6852193,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.699694252,
      "finished_wall": 1792089355.7107582,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.689689987,
      "started_wall": 1792089355.7007537,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.715242573,
      "finished_wall": 1792089355.7263067,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.704786087,
      "started_wall": 1792089355.7158496,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.731057019,
      "finished_wall": 1792089355.742121,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.720336431,
      "started_wall": 1792089355.7314,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.746730893,
      "finished_wall": 1792089355.7577949,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.736153893,
      "started_wall": 1792089355.7472174,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.76275009,
      "finished_wall": 1792089355.773814,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.751827466,
      "started_wall": 1792089355.762891,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.769257989,
      "finished_wall": 1792089355.780322,
      "http_status": 429,
      "lease_deadline": 502.141886122,
      "response_valid": false,
      "started_monotonic": 501.767851061,
      "started_wall": 1792089355.7789145,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.775544126,
      "finished_wall": 1792089355.7866082,
      "http_status": 429,
      "lease_deadline": 502.141886122,
      "response_valid": false,
      "started_monotonic": 501.774332511,
      "started_wall": 1792089355.7853959,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.782032328,
      "finished_wall": 1792089355.7930965,
      "http_status": 429,
      "lease_deadline": 502.141886122,
      "response_valid": false,
      "started_monotonic": 501.78062513,
      "started_wall": 1792089355.7916887,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.788212177,
      "finished_wall": 1792089355.799276,
      "http_status": 429,
      "lease_deadline": 502.141886122,
      "response_valid": false,
      "started_monotonic": 501.787132428,
      "started_wall": 1792089355.798196,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.794376206,
      "finished_wall": 1792089355.8054402,
      "http_status": 429,
      "lease_deadline": 502.141886122,
      "response_valid": false,
      "started_monotonic": 501.793289254,
      "started_wall": 1792089355.8043528,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.810539591,
      "finished_wall": 1792089355.8216035,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.799456349,
      "started_wall": 1792089355.8105197,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.81679462,
      "finished_wall": 1792089355.8278584,
      "http_status": 429,
      "lease_deadline": 502.141886122,
      "response_valid": false,
      "started_monotonic": 501.815640302,
      "started_wall": 1792089355.8267038,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.822985169,
      "finished_wall": 1792089355.834049,
      "http_status": 429,
      "lease_deadline": 502.141886122,
      "response_valid": false,
      "started_monotonic": 501.821872749,
      "started_wall": 1792089355.8329363,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.829235669,
      "finished_wall": 1792089355.8402996,
      "http_status": 429,
      "lease_deadline": 502.141886122,
      "response_valid": false,
      "started_monotonic": 501.828030948,
      "started_wall": 1792089355.8390942,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.83552446,
      "finished_wall": 1792089355.8465884,
      "http_status": 429,
      "lease_deadline": 502.141886122,
      "response_valid": false,
      "started_monotonic": 501.834311093,
      "started_wall": 1792089355.8453743,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.841828521,
      "finished_wall": 1792089355.8528926,
      "http_status": 429,
      "lease_deadline": 502.141886122,
      "response_valid": false,
      "started_monotonic": 501.84060274,
      "started_wall": 1792089355.8516662,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.857519627,
      "finished_wall": 1792089355.8685834,
      "http_status": 200,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.846906058,
      "started_wall": 1792089355.8579698,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.863798951,
      "finished_wall": 1792089355.874863,
      "http_status": 429,
      "lease_deadline": 502.141886122,
      "response_valid": false,
      "started_monotonic": 501.862620338,
      "started_wall": 1792089355.873684,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.870066192,
      "finished_wall": 1792089355.88113,
      "http_status": 429,
      "lease_deadline": 502.141886122,
      "response_valid": false,
      "started_monotonic": 501.868876168,
      "started_wall": 1792089355.8799398,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.876242995,
      "finished_wall": 1792089355.887307,
      "http_status": 429,
      "lease_deadline": 502.141886122,
      "response_valid": false,
      "started_monotonic": 501.875141636,
      "started_wall": 1792089355.8862052,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.882420059,
      "finished_wall": 1792089355.8934844,
      "http_status": 429,
      "lease_deadline": 502.141886122,
      "response_valid": false,
      "started_monotonic": 501.881318048,
      "started_wall": 1792089355.8923817,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.888655631,
      "finished_wall": 1792089355.8997197,
      "http_status": 429,
      "lease_deadline": 502.141886122,
      "response_valid": false,
      "started_monotonic": 501.887496915,
      "started_wall": 1792089355.8985605,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.895268182,
      "finished_wall": 1792089355.9063323,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.893731095,
      "started_wall": 1792089355.9047947,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.901915902,
      "finished_wall": 1792089355.91298,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.900355598,
      "started_wall": 1792089355.9114192,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.908794694,
      "finished_wall": 1792089355.919859,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.907002199,
      "started_wall": 1792089355.9180655,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.915583245,
      "finished_wall": 1792089355.9266472,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.913896447,
      "started_wall": 1792089355.92496,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.922427891,
      "finished_wall": 1792089355.933492,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.92064289,
      "started_wall": 1792089355.9317064,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.929150159,
      "finished_wall": 1792089355.9402142,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.927555602,
      "started_wall": 1792089355.9386191,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.935985378,
      "finished_wall": 1792089355.9470496,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.934232205,
      "started_wall": 1792089355.9452956,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.942756238,
      "finished_wall": 1792089355.9538205,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.941132715,
      "started_wall": 1792089355.9521964,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.949398793,
      "finished_wall": 1792089355.9604628,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.947856195,
      "started_wall": 1792089355.9589198,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.9559219,
      "finished_wall": 1792089355.9669862,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.954487681,
      "started_wall": 1792089355.9655514,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.962509287,
      "finished_wall": 1792089355.9735734,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.961043122,
      "started_wall": 1792089355.9721067,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.970817429,
      "finished_wall": 1792089355.9818819,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.967592295,
      "started_wall": 1792089355.978656,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.977525227,
      "finished_wall": 1792089355.988589,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.975917188,
      "started_wall": 1792089355.9869807,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.984077303,
      "finished_wall": 1792089355.9951413,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.982618725,
      "started_wall": 1792089355.9936821,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.990398731,
      "finished_wall": 1792089356.0014627,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.989161754,
      "started_wall": 1792089356.0002253,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 501.996662656,
      "finished_wall": 1792089356.0077267,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 501.995485316,
      "started_wall": 1792089356.006549,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.002773356,
      "finished_wall": 1792089356.0138373,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.001741657,
      "started_wall": 1792089356.0128052,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.008881492,
      "finished_wall": 1792089356.0199454,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.00784897,
      "started_wall": 1792089356.0189126,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.014972365,
      "finished_wall": 1792089356.0260363,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.013957266,
      "started_wall": 1792089356.0250208,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.021056997,
      "finished_wall": 1792089356.0321212,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.020023243,
      "started_wall": 1792089356.031087,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.027172305,
      "finished_wall": 1792089356.0382364,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.026131459,
      "started_wall": 1792089356.037195,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.033233634,
      "finished_wall": 1792089356.0442977,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.032249402,
      "started_wall": 1792089356.0433128,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.039303097,
      "finished_wall": 1792089356.050367,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.038308446,
      "started_wall": 1792089356.049372,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.045550111,
      "finished_wall": 1792089356.0566142,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.044379543,
      "started_wall": 1792089356.055443,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.051908782,
      "finished_wall": 1792089356.062973,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.05063408,
      "started_wall": 1792089356.0616977,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.058131341,
      "finished_wall": 1792089356.0691955,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.056987673,
      "started_wall": 1792089356.068051,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.064202597,
      "finished_wall": 1792089356.0752666,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.063208457,
      "started_wall": 1792089356.074272,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.070223871,
      "finished_wall": 1792089356.0812879,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.069278101,
      "started_wall": 1792089356.0803418,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.076272516,
      "finished_wall": 1792089356.0873365,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.075299776,
      "started_wall": 1792089356.0863633,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.082305812,
      "finished_wall": 1792089356.0933695,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.081346537,
      "started_wall": 1792089356.09241,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.08835661,
      "finished_wall": 1792089356.0994203,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.087381376,
      "started_wall": 1792089356.098445,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.09450474,
      "finished_wall": 1792089356.105569,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.093431744,
      "started_wall": 1792089356.1044953,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.100583972,
      "finished_wall": 1792089356.111648,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.099581016,
      "started_wall": 1792089356.1106446,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.106754033,
      "finished_wall": 1792089356.117818,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.10566142,
      "started_wall": 1792089356.116725,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.112801144,
      "finished_wall": 1792089356.1238651,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.111828675,
      "started_wall": 1792089356.1228924,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.118795989,
      "finished_wall": 1792089356.1298602,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.117876348,
      "started_wall": 1792089356.12894,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.124830988,
      "finished_wall": 1792089356.1358953,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.123871743,
      "started_wall": 1792089356.1349354,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.130767444,
      "finished_wall": 1792089356.1418312,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.129907975,
      "started_wall": 1792089356.1409714,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.136681248,
      "finished_wall": 1792089356.1477451,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.135840293,
      "started_wall": 1792089356.1469038,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.142656666,
      "finished_wall": 1792089356.1537206,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.141753466,
      "started_wall": 1792089356.1528172,
      "trust_sequence": 28
    },
    {
      "finished_monotonic": 502.148557386,
      "finished_wall": 1792089356.1596212,
      "http_status": 503,
      "lease_deadline": 502.141886122,
      "response_valid": true,
      "started_monotonic": 502.147729886,
      "started_wall": 1792089356.1587934,
      "trust_sequence": 28
    }
  ],
  "recovery_verified": {
    "deadline": 563.702749473,
    "document_sha256": "9f6db13deca7e5dbcc48ec6ac8713c2cd08af575c344f15118621233bd2c27d9",
    "monotonic": 503.714909439,
    "sequence": 33,
    "version": 1,
    "wall": 1792089357.725973
  },
  "release_ready": false,
  "schema_version": 1,
  "status": "fail"
}
```

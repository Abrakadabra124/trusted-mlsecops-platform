"""Dependency-free browser controller. No persistence, writes or external origins."""

SCRIPT = r"""'use strict';
(() => {
  const el = id => document.getElementById(id);
  const series = {change_size:'Размер изменения',failed_checks:'Неуспешные проверки',dependency_changes:'Изменения зависимостей',test_coverage:'Покрытие тестами',change_entropy:'Неоднородность изменения',prior_failure_rate:'Предыдущие отказы',prediction:'Предсказание'};
  const kinds = {data_drift:'Сдвиг входных данных',prediction_drift:'Сдвиг предсказаний',quality_degradation:'Ухудшение качества',telemetry_gap:'Разрыв телеметрии'};
  const faults = {clock:'Часы',observation:'Сбор наблюдений',queue:'Очередь',delivery:'Доставка',scheduler:'Планировщик',shutdown:'Завершение'};
  const states = {observing:'Сбор активен',inactive:'Не запущен',stopped:'Остановлен'};
  const dataStates = {observed:'Достаточно данных',insufficient:'Недостаточно данных'};
  let token = '', generation = 0, active = null, timer = null, activeDeadline = null;
  const text = (id, value) => { el(id).textContent = String(value); };
  const message = (value, kind='') => { text('connection', value); el('connection').className = 'notice ' + kind; };
  const integer = n => { if (!Number.isSafeInteger(n) || n < 0) throw Error('schema'); return n; };
  const number = n => { if (typeof n !== 'number' || !Number.isFinite(n) || n < 0) throw Error('schema'); return n; };
  const list = (v, max) => { if (!Array.isArray(v) || v.length > max) throw Error('schema'); return v; };
  const choice = (v, choices) => { if (typeof v !== 'string' || !Object.hasOwn(choices, v)) throw Error('schema'); return v; };
  const hash = (v, size) => { if (typeof v !== 'string' || !new RegExp('^[a-f0-9]{'+size+'}$').test(v)) throw Error('schema'); return v; };
  function checked(s) {
    if (!s || s.schema_version !== 1 || s.release_ready !== false || typeof s.healthy !== 'boolean' || s.history_restored !== false) throw Error('schema');
    choice(s.state, states); choice(s.data_status, dataStates); hash(s.reference_sha256,64); hash(s.epoch,32);
    ['observations','windows_evaluated','pending_windows','pending_alerts','alerts_delivered','delivery_failures','evicted_windows','unclosed_observations'].forEach(k => integer(s[k]));
    list(s.faults,6).forEach(f => choice(f,faults));
    list(s.reports,20).forEach(r => {
      integer(r.sequence); integer(r.observations); choice(r.status,dataStates); choice(r.prediction_status,dataStates);
      if (r.reference_sha256 !== s.reference_sha256 || r.release_ready !== false) throw Error('schema');
      hash(r.window_sha256,64); Object.keys(series).forEach(k => {
        const status=k==='prediction'?r.prediction_status:r.status;
        if(status==='insufficient'){if(r.psi[k]!==null)throw Error('schema');}else number(r.psi[k]);
      });
      list(r.alerts,3).forEach(k => choice(k,kinds));
    });
    list(s.label_reports,20).forEach(r => {
      choice(r.status,dataStates); integer(r.positives); integer(r.true_positives);
      if (r.reference_sha256 !== s.reference_sha256 || r.release_ready !== false || r.true_positives > r.positives || ![null,'quality_degradation'].includes(r.alert)) throw Error('schema');
      hash(r.window_sha256,64);
    });
    list(s.receipts,128).forEach(r => { choice(r.kind,kinds); number(r.delivery_seconds); integer(r.received_at_ms); if (r.received_at_ms > 8640000000000000) throw Error('schema'); });
    return s;
  }
  function clear() {
    ['observations','windows','delivered','positives','true-positives','recall','reference','epoch'].forEach(id => text(id,'-'));
    ['psi','window-rows','receipts'].forEach(id => el(id).replaceChildren());
    ['drift-empty','windows-empty','receipts-empty'].forEach(id => { el(id).hidden = false; });
    text('state','Нет свежих данных'); text('health','Состояние не проверено'); text('pending','Ожидание данных'); text('delivery','Ожидание данных');
    text('data-status','Нет данных'); text('quality-status','Нет данных'); text('quality-message','Подтверждённые метки ещё не получены.'); text('history','Не проверена'); text('faults','Сведения о сбоях не получены.');
    el('faults').className='notice';
  }
  function row(parent, values) {
    const tr = document.createElement('tr');
    values.forEach(value => { const td = document.createElement('td'); if (typeof value === 'object') td.append(value); else td.textContent=String(value); tr.append(td); });
    parent.append(tr);
  }
  function render(s) {
    clear(); text('state',states[s.state]); text('health',s.healthy?'Телеметрия доступна':'Требуется проверка телеметрии');
    text('observations',s.observations.toLocaleString('ru-RU')); text('windows',s.windows_evaluated); text('pending','В очереди: '+s.pending_windows+' · Незакрытых наблюдений: '+s.unclosed_observations);
    text('delivered',s.alerts_delivered); text('delivery','Ожидают: '+s.pending_alerts+' · Ошибок доставки: '+s.delivery_failures);
    text('data-status',dataStates[s.data_status]); text('reference',s.reference_sha256); text('epoch',s.epoch);
    text('history','Не восстановлена. Показан текущий epoch.');
    text('faults',s.faults.length?'Сбои: '+s.faults.map(k=>faults[k]).join(', '):'Активных сбоев сбора и доставки нет.'); el('faults').className='notice '+(s.faults.length?'bad':'good');
    const latest=s.reports.at(-1);
    if (latest) {
      el('drift-empty').hidden=true;
      Object.entries(series).forEach(([k,label])=>{
        const value=latest.psi[k];
        if(value===null){row(el('psi'),[label,'Недостаточно данных','-']);return;}
        const meter=document.createElement('meter'); meter.min=0;meter.max=1;meter.high=0.2;meter.optimum=0;meter.value=Math.min(value,1);meter.setAttribute('aria-label',label+': PSI '+value.toFixed(4));row(el('psi'),[label,value.toFixed(4),meter]);
      });
    }
    s.reports.slice().reverse().forEach(r=>row(el('window-rows'),[r.sequence,r.observations,dataStates[r.status],r.alerts.length?r.alerts.map(k=>kinds[k]).join(', '):r.status==='insufficient'?'Оценка не завершена':'Нет сигналов']));
    el('windows-empty').hidden=s.reports.length>0;
    const quality=s.label_reports.at(-1);
    if (quality) { text('positives',quality.positives);text('true-positives',quality.true_positives);text('recall',quality.positives?(quality.true_positives/quality.positives*100).toFixed(1)+'%':'Не определён');text('quality-status',dataStates[quality.status]);text('quality-message',quality.alert?'Получен сигнал ухудшения качества':quality.status==='insufficient'?'Недостаточно положительных меток для вывода.':'Сигнал ухудшения качества не получен.'); }
    s.receipts.slice(-8).reverse().forEach(r=>{const li=document.createElement('li'), detail=document.createElement('small');li.textContent=kinds[r.kind];detail.textContent=(r.delivery_seconds*1000).toFixed(0)+' мс · '+new Date(r.received_at_ms).toLocaleTimeString('ru-RU');li.append(detail);el('receipts').append(li);});
    el('receipts-empty').hidden=s.receipts.length>0;
    text('updated','Получено: '+new Date().toLocaleTimeString('ru-RU')+' · Автообновление: 5 с');
    message(s.healthy?'Подключено. Показаны свежие данные.':'Подключено. Система сообщает о проблеме телеметрии.',s.healthy?'good':'warn');
  }
  async function body(response) {
    if (!response.headers.get('content-type')?.startsWith('application/json')) throw Error('schema');
    const reader=response.body.getReader(),chunks=[];let length=0;
    while (true) { const {done,value}=await reader.read();if(done)break;length+=value.byteLength;if(length>262144)throw Error('schema');chunks.push(value); }
    const bytes=new Uint8Array(length);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
    return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
  }
  function disconnect(note='Отключено. Ключ удалён из памяти вкладки.') {
    generation++;token='';clearTimeout(timer);timer=null;clearTimeout(activeDeadline);activeDeadline=null;if(active)active.abort();active=null;el('credential').value='';
    el('disconnect').disabled=true;el('refresh').disabled=true;clear();text('updated','Свежие данные не получены.');message(note);
  }
  async function poll() {
    if (!token || active) return;
    const own=generation,controller=new AbortController();active=controller;let delay=5000;
    el('refresh').disabled=true;
    const deadline=setTimeout(()=>controller.abort(),5000);
    activeDeadline=deadline;
    try {
      const response=await fetch('/monitoring',{method:'GET',headers:{Authorization:'Bearer '+token},credentials:'omit',cache:'no-store',redirect:'error',signal:controller.signal});
      if(own!==generation)return;
      if(response.status===401){disconnect('Доступ отклонён. Введите действующий ключ оператора.');return;}
      if(response.status===429)throw Error('limited');
      if(![200,503].includes(response.status))throw Error('unavailable');
      const value=checked(await body(response));
      if(own!==generation)return;
      if((response.status===200)!==value.healthy)throw Error('schema');
      render(value);
    } catch(error) {
      if(own!==generation)return;
      clear();text('updated','Нет свежих данных. Последнее состояние больше не считается текущим.');
      delay=error.message==='limited'?30000:10000;
      message(error.message==='limited'?'Лимит запросов. Следующая попытка через 30 секунд.':'Не удалось получить проверяемое состояние. Следующая попытка через 10 секунд.','warn');
    } finally {
      clearTimeout(deadline);controller.abort();
      if(own===generation){active=null;activeDeadline=null;el('refresh').disabled=!token;if(token)timer=setTimeout(poll,delay);}
    }
  }
  el('connect').addEventListener('submit',event=>{event.preventDefault();const entered=el('credential').value;disconnect();if(!/^[a-f0-9]{64}$/.test(entered)){message('Введите ключ из 64 строчных шестнадцатеричных символов.','warn');return;}token=entered;el('disconnect').disabled=false;message('Проверяю доступ и состояние…');void poll();});
  el('disconnect').addEventListener('click',()=>disconnect());
  el('refresh').addEventListener('click',()=>{clearTimeout(timer);void poll();});
  window.addEventListener('pagehide',()=>disconnect());
})();
"""

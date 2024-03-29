var Editor = Editor || {};

(function() {
  var STATE = { BASE: 0, IN_PARAGRAPH: 1, IN_LIST: 2, IN_ENTRY: 3 };

  var PATT = {
    EMTPY: /^\s*$/,
    HEAD: /^\!(.+)\s*$/,
    LIST: /^\*\s+(.*\S)\s*$/, // trim trailing space
    ENTRY: /^(\w.*):\s+(.+) \/ (.+)$/,
    NOTE: /^\s+(.*\S)\s*$/ // trim trailing space
  };

  var doTopt = $.extend({}, doT.templateSettings, {strip: false});

  var TOHTML = {
    'heading': doT.template('<div class="row"><div class="col-md-12">' +
      '<h2 id="elem{{=it.id}}" contenteditable="true">{{=it.value}}</h2>' +
      '</div></div>'),
    'paragraph': doT.template('<div class="row"><div class="col-md-12">' +
        '<p id="elem{{=it.id}}" contenteditable="true">{{=it.value.join("<br>")}}</p>' +
        '</div></div>'),
    'list': doT.template('<div class="row"><div class="col-md-12">' +
      '<ul id="elem{{=it.id}}" contenteditable="true">' +
      '{{~it.value :value:index}}' +
      '<li>{{=value}}</li>' +
      '{{~}}' +
      '</ul>' +
      '</div></div>'),
    'entry': doT.template('<div id="elem{{=it.id}}" class="row entry">' +
        '<div class="col-xs-12 col-md-3"><p class="name" contenteditable="true">{{=it.value.name}}</p></div>' +
        '<div class="col-xs-12 col-sm-6 col-md-3"><p class="username" contenteditable="true">{{=it.value.username}}</p></div>' +
        '<div class="col-xs-9 col-sm-4 col-md-3"><p class="password" contenteditable="true">{{=it.value.password}}</p></div>' +
        '<div class="col-xs-3 col-sm-2">' +
        '<a href="#" class="moreless">' +
        '{{? it.value.notes.length }}' +
        '<span class="glyphicon glyphicon-comment text-primary" aria-hidden="true"></span>' +
        '{{??}}' +
        '<span class="glyphicon glyphicon-comment" aria-hidden="true"></span>' +
        '{{?}}' +
        '</a>' +
        '</div>' +
        '<div class="col-xs-12">' +
        '<blockquote class="notes" contenteditable="true">{{=it.value.notes.join("<br>")}}</blockquote>' +
        '</div>' +
        '</div>'),
    'entry_end': doT.template('<div class="row"><div class="col-md-12">' +
        '<button id="elem{{=it.id}}" class="addbutton btn btn-default">' +
        '<span class="glyphicon glyphicon-plus" aria-hidden="true"></span> Add new entry' +
        '</button> ' +
        '<button id="elem{{=it.id}}" class="sortbutton btn btn-default">' +
        '<span class="glyphicon glyphicon-sort" aria-hidden="true"></span> Sort entries' +
        '</button>' +
        '</div></div>', doTopt)
  };

  var TOTEXT = {
    'heading': doT.template('!{{=it.value}}\n\n', doTopt),
    'paragraph': doT.template('{{=it.value.join("\\n")}}\n\n', doTopt),
    'list': doT.template('{{~it.value :value:index}}* {{=value}}\n{{~}}\n', doTopt),
    'entry': doT.template('{{=it.value.name}}: {{=it.value.username}} / {{=it.value.password}}\n' +
        '{{? it.value.notes.length }}  {{=it.value.notes.join("\\n  ")}}\n{{?}}', doTopt),
    'entry_end': doT.template('\n', doTopt)
  };

  Editor.Editor = function() {
    this.clearElements();
  };

  Editor.Editor.prototype.clearElements = function(type, value) {
    this.elements = [];
    this.elementMap = {};
    this.nextId = 0;
  };

  Editor.Editor.prototype.createElement = function(type, value, omitAdd) {
    var elem = {id: this.nextId++, type: type, value: value};
    this.elementMap[elem.id] = elem;
    if(!omitAdd) this.elements.push(elem.id);
    return elem;
  };

  // Initialize elements from text
  Editor.Editor.prototype.fromText = function(text) {
    var lines = text.split('\n'), i, state = STATE.BASE;
    var element = null;

    this.clearElements();

    for(i = 0; i < lines.length; i++) {
      var line = lines[i], match;

      if(PATT.EMTPY.exec(line) !== null) {
        state = STATE.BASE; // return to base state
      } else if((match = PATT.HEAD.exec(line)) !== null) {
        element = this.createElement('heading', match[1]);
        state = STATE.BASE; // not in para, list, entry any more
      } else if((match = PATT.LIST.exec(line)) !== null) {
        if(state != STATE.IN_LIST) { // create new object
          element = this.createElement('list', []);
          state = STATE.IN_LIST;
        }
        element.value.push(match[1]); // append item
      } else if((match = PATT.ENTRY.exec(line)) !== null) {
        element = this.createElement('entry', {
          name: match[1],
          username: match[2],
          password: match[3],
          notes: []
        });
        state = STATE.IN_ENTRY;
      } else if(state == STATE.IN_ENTRY &&
          (match = PATT.NOTE.exec(line)) !== null) {
        element.value.notes.push(match[1]);
      } else {
        if(state != STATE.IN_PARAGRAPH) { // create new object
          element = this.createElement('paragraph', []);
          state = STATE.IN_PARAGRAPH;
        }
        element.value.push(line);
      }
    }

    // Nice for loop to insert entry_end after consecutive entries
    var wasEntry = false, added = [];

    for(i=0; i<this.elements.length; i++) {
      var elem = this.elementMap[this.elements[i]];

      if(wasEntry && elem.type != 'entry') {
        var end = this.createElement('entry_end', null, true);
        added.push(end.id);
      }
      added.push(elem.id);
      wasEntry = (elem.type == 'entry');
    }

    if(wasEntry) { // one more for the road
      var end = this.createElement('entry_end', null, true);
      added.push(end.id);
    }

    this.elements = added;
  };

  Editor.Editor.prototype.toHtml = function() {
    var html = '', i;
    for(i = 0; i < this.elements.length; i++) {
      var elem = this.elementMap[this.elements[i]];
      html += TOHTML[elem.type](elem);
    }
    return html;
  };


  Editor.Editor.prototype.toText = function() {
    var text = '', i;
    for(i = 0; i < this.elements.length; i++) {
      var elem = this.elementMap[this.elements[i]];
      text += TOTEXT[elem.type](elem);
    }
    return text;
  };

  // Normalize webkit <div> linebreaks to <br> and remove all other tags
  function splitEditable(html) {
    html = html.replace(/<div>/gi, '\n'); // Assume Webkit line break
    html = html.replace(/<br>/gi, '\n'); // Firefox et al.
    html = html.replace(/<[^>]+>/gi, ''); // Remove all other tags
    return html.split('\n');
  }

  Editor.Editor.prototype.attachListeners = function(elemId) {
    var me = this;

    // Watch changes on editable elements
    $(elemId).on('blur', '[contenteditable]', function(ev) {
      var id = $(this).attr('id');

      if(id && id.substr(0,4) == 'elem') { // atomic editable elements
        id = id.substr(4);
        var elem = me.elementMap[parseInt(id)];
        switch(elem.type) {
          case 'heading':
            $(this).html($(this).text()); // Remove formatting
            elem.value = $(this).html();
            break;
          case 'paragraph':
            elem.value = splitEditable($(this).html());
            $(this).html(elem.value.join('<br>'));
            break;
          case 'list':
            elem.value = [];
            $(this).children('li').each(function(idx, item) {
              $(item).html($(item).text()); // Remove formatting
              elem.value.push($(item).text());
            });
            break;
        }
      } else { // entry
        var entry = $(this).closest('.entry'), cls = $(this).attr('class');
        var id = parseInt(entry.attr('id').substr(4));

        if(cls == 'notes') {
          me.elementMap[id].value.notes = splitEditable($(this).html());
          $(this).html(me.elementMap[id].value.notes.join('<br>'));
        } else {
          $(this).html($(this).text()); // Remove formatting
          me.elementMap[id].value[cls] = $(this).text();
        }
      }
    });

    $(elemId).on('click', '.moreless', function(ev) {
      var field = $(this).closest('.entry').find('.notes');
      if(field.is(':visible'))
        field.hide(400);
      else
        field.show(400);
      return false;
    });

    $(elemId).on('click', '.addbutton', function(ev) {
      var id = parseInt($(this).attr('id').substr(4));
      var name, username, password;

      if(null === (name = prompt('Enter service name')))
        return false;
      if(null === (username = prompt('Enter service username')))
        return false;
      if(null === (password = prompt('Enter service password')))
        return false;

      var pos = me.elements.indexOf(id);
      var elem = me.createElement('entry', {
        name: name,
        username: username,
        password: password,
        notes: []
      }, true); // omit adding to elements

      me.elements.splice(pos, 0, elem.id); // insert in middle

      $(TOHTML['entry'](elem)).insertBefore($(this).closest('.row'));

      return false;
    });

    $(elemId).on('click', '.sortbutton', function(ev) {
      var id = parseInt($(this).attr('id').substr(4));
      var pos = me.elements.indexOf(id), i = pos;
      var buttonrow = $(this).closest('.row');

      while(--i >= 0) { // 'entry' at 0 results in i == -1
        var elem = me.elementMap[me.elements[i]];
        if(elem.type != 'entry') break;
        $('#elem' + elem.id).remove(); // remove from old position
      } 

      var entries = me.elements.splice(i+1, pos-i-1);
      
      entries.sort(function(a,b) {
        var ae = me.elementMap[a].value, be = me.elementMap[b].value;
        return ae.name < be.name ? -1 : (ae.name > be.name ? 1 : 0);
      });

      entries.forEach(function(id) {
        var elem = me.elementMap[id];
        $(TOHTML['entry'](elem)).insertBefore(buttonrow);
      });

      me.elements.splice.apply(me.elements, [i+1, 0].concat(entries));
      //alert('Now I would sort from ' + i + ' to ' + pos);

      return false;
    });
  };
})();

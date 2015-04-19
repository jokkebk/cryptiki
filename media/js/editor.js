var Editor = Editor || {};

(function() {
    var STATE = {
        BASE: 0, IN_PARAGRAPH: 1, IN_LIST: 2, IN_ENTRY: 3
    };

    var PATT = {
        EMTPY: /^\s*$/,
        HEAD: /^\!(.+)\s*$/,
        LIST: /^\*\s+(.*\S)\s*$/,
        ENTRY: /^(\w.*):\s+([^\/]+)\s+\/ (.+)$/,
        FIELD: /^\s+([^:]+):\s(.+)$/
    };

    var TPL = {
        'heading': doT.template('<h1 id="elem{{=it.id}}" contenteditable="true">{{=it.value}}</h1>'),
        'list': doT.template(
            '<ul id="elem{{=it.id}}" contenteditable="true">' +
                '{{~it.value :value:index}}' +
                '<li>{{=value}}</li>' +
                '{{~}}' +
                '</ul>'
        ),
        'paragraph': doT.template('<p id="elem{{=it.id}}" contenteditable="true">{{=it.value.join("<br>")}}</p>'),
        'entry': doT.template(
            '<div id="elem{{=it.id}}" class="entry">' +
                '<div class="name" contenteditable="true">{{=it.name}}</div>' +
                '<div class="username" contenteditable="true">{{=it.username}}</div>' +
                '<div class="password" contenteditable="true">{{=it.password}}</div>' +
                '<div class="tools">' +
                '<a href="#" class="newfield">New field</a>' +
                '{{? !$.isEmptyObject(it.value) }}' +
                ' <a href="#" class="moreless">[+]</a>' +
                '{{?}}' +
                '</div>' +
                '<div style="clear: both;"></div>' +
                '<div class="fields" style="display: none;">' +
                '<dl>' +
                '{{ for(var key in it.value) { }}' +
                '<dt><img src="/media/icon/delete.png" class="removefield"> <span>{{=key}}</span>:</dt>' +
                '<dd contenteditable="true">{{=it.value[key]}}</dd>' +
                '{{ } }}' +
                '</dl>' +
                '<div style="clear: both;"></div>' +
                '</div>' + // fields
                '</div>'
        ),
        'field': doT.template( // should be identical to above except property interpolation
            '<dt><img src="/media/icon/delete.png" class="removefield"> <span>{{=it.key}}</span>:</dt>' +
                '<dd contenteditable="true">{{=it.value}}</dd>'
        )
    };

    function Element(id, type, value) {
        this.id = id;
        this.type = type;
        this.value = value;
    };

    Element.prototype.toHtml = function() {
        if(this.type in TPL)
            return TPL[this.type](this);

        return ''; // unknown type
    };

    Element.prototype.toText = function() {
        switch(this.type) {
            case 'heading':
                return '!' + this.value + '\n\n';
                break;
            case 'paragraph':
                return this.value.join('\n') + '\n\n';
                break;
            case 'list':
                return '* ' + this.value.join('\n* ') + '\n\n';
                break;
            case 'entry':
                var text = this.name + ': ' + this.username + ' / ' + this.password + '\n';
                for(var key in this.value) {
                    if(this.value.hasOwnProperty(key))
                        text += '  ' + key + ': ' + this.value[key] + '\n';
                }
                //text += '\n';
                return text;
        }
        return ''; // unknown type
    };

    Element.prototype.fromHtml = function(elem) {
        switch(this.type) {
            case 'heading':
                this.value = elem.html();
                break;
            case 'paragraph':
                this.value = elem.html().split('<br>');
                break;
            case 'list':
                var list = this.value = [];
                elem.children('li').each(function(idx, item) {
                    var html = $(item).html();
                    html = html.replace('<br>', '');
                    list.push(html);
                });
                break;
            case 'entry':
                alert('Not implemented yet!');
                break;
        }
    };

    Editor.Editor = function() {
        this.clearElements();
    };

    Editor.Editor.prototype.clearElements = function(type, value) {
        this.elements = [];
        this.elementMap = {};
        this.nextId = 0;
    };

    Editor.Editor.prototype.createElement = function(type, value) {
        var elem = new Element(this.nextId++, type, value);
        this.elementMap[elem.id] = elem;
        this.elements.push(elem.id);

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
                continue; // go to next line
            }

            if((match = PATT.HEAD.exec(line)) !== null) {
                element = this.createElement('heading', match[1]);
                state = STATE.BASE; // not in para, list, entry any more
            } else if((match = PATT.LIST.exec(line)) !== null) {
                if(state != STATE.IN_LIST) { // create new object
                    element = this.createElement('list', []);
                    state = STATE.IN_LIST;
                }
                element.value.push(match[1]); // append item
            } else if((match = PATT.ENTRY.exec(line)) !== null) {
                // create new entry object
                element = this.createElement('entry', {});
                element.name = match[1];
                element.username = match[2];
                element.password = match[3];
                state = STATE.IN_ENTRY;
            } else if(state == STATE.IN_ENTRY &&
                (match = PATT.FIELD.exec(line)) !== null) {
                    element.value[match[1]] = match[2]; // set name/value pair
                } else {
                    if(state != STATE.IN_PARAGRAPH) { // create new object
                        element = this.createElement('paragraph', []);
                        state = STATE.IN_PARAGRAPH;
                    }
                    element.value.push(line);
                }
        }
    };

    Editor.Editor.prototype.toHtml = function() {
        var html = '', i;
        for(i = 0; i < this.elements.length; i++)
            html += this.elementMap[this.elements[i]].toHtml();
        return html;
    };


    Editor.Editor.prototype.toText = function() {
        var text = '', i;
        for(i = 0; i < this.elements.length; i++)
            text += this.elementMap[this.elements[i]].toText();
        return text;
    };

    Editor.Editor.prototype.attachListeners = function(elemId) {
        var me = this;

        // Watch changes on editable elements
        $(elemId).on('blur', '[contenteditable]', function(ev) {
          var id = $(this).attr('id');

          if(id && id.substr(0,4) == 'elem') { // atomic editable elements
            id = id.substr(4);
            me.elementMap[parseInt(id)].fromHtml($(this));
          } else { // entry
            var entry = $(this).closest('.entry'), cls = $(this).attr('class'),
                id = parseInt(entry.attr('id').substr(4));

            switch(cls) {
              case 'name': case 'username': case 'password':
                me.elementMap[id][cls] = $(this).html().replace('<br>', '');
                break;
              default:
                me.elementMap[id].value[$(this).prev().html()] =
                  $(this).html().replace('<br>', ' ');
                break;
            }
          }
        });

        $(elemId).on('click', '.moreless', function(ev) {
          var field = $(this).closest('.entry').children('.fields');

          if(field.is(':visible')) {
            field.hide(400);
            $(this).html('[+]');
          } else {
            field.show(400);
            $(this).html('[-]');
          }

          return false;
        });

        $(elemId).on('click', '.removefield', function(ev) {
          var field = $(this).next().html(), parent = $(this).parent(),
              entry = $(this).closest('.entry'),
              id = parseInt(entry.attr('id').substr(4));

          parent.next().remove(); // remove dd
          parent.remove(); // remove dt
          delete me.elementMap[id].value[field]; // remove data
        });

        $(elemId).on('click', '.newfield', function(ev) {
          var entry = $(this).closest('.entry'), dl = entry.find('dl'),
              id = parseInt(entry.attr('id').substr(4)),
              name = prompt('Give field a name');

          if(!name || name === '') return false;

          if(name in me.elementMap[id].value) {
            alert(name + ' already exists!');
          } else {
            var value = prompt('Give value for field');

            if(value && value !== '') {
              if($.isEmptyObject(me.elementMap[id].value)) { // first element
                me.elementMap[id].value[name] = value; // add name/value field
                entry.replaceWith(TPL.entry(me.elementMap[id]));
              } else { // existing elements, and thus [+] / [-]
                me.elementMap[id].value[name] = value; // add name/value field
                dl.append(TPL.field({key: name, value: value}));
              }
            }
          }

          return false;
        });
    };
})();

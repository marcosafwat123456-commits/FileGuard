(function () {
  "use strict";

  const elements = {
    courseCount: document.getElementById("course-count"),
    courseList: document.getElementById("course-list"),
    courseContent: document.getElementById("course-content"),
    search: document.getElementById("course-search"),
    dialog: document.getElementById("course-dialog"),
    form: document.getElementById("course-form"),
    dialogTitle: document.getElementById("dialog-title"),
    courseName: document.getElementById("course-name"),
    saveCourse: document.getElementById("save-course"),
    themeToggle: document.getElementById("theme-toggle"),
    themeIcon: document.getElementById("theme-icon"),
    themeLabel: document.getElementById("theme-label"),
    toast: document.getElementById("toast")
  };

  let database;
  let courses = [];
  let selectedCourseId = null;
  let editingCourseId = null;
  let notesTimer = null;
  let toastTimer = null;

  function readThemePreference() {
    try {
      const savedTheme = localStorage.getItem("mawaddi-theme");
      return savedTheme === "dark" ? "dark" : "light";
    } catch (error) {
      console.warn("Could not read the saved theme preference:", error);
      return "light";
    }
  }

  function applyTheme(theme, persist) {
    const isDark = theme === "dark";
    document.documentElement.dataset.theme = isDark ? "dark" : "light";
    elements.themeToggle.setAttribute("aria-pressed", String(isDark));
    elements.themeToggle.setAttribute("aria-label", isDark ? "تفعيل الوضع الفاتح" : "تفعيل الوضع الداكن");
    elements.themeIcon.textContent = isDark ? "☀" : "☾";
    elements.themeLabel.textContent = isDark ? "الوضع الفاتح" : "الوضع الداكن";
    document.querySelector('meta[name="theme-color"]').content = isDark ? "#111720" : "#f5f7fb";
    if (persist) {
      try {
        localStorage.setItem("mawaddi-theme", isDark ? "dark" : "light");
      } catch (error) {
        console.error("Could not save the theme preference:", error);
        showToast("تغير المظهر، لكن تعذر حفظ الاختيار على هذا الجهاز.", true);
      }
    }
  }

  function openDatabase() {
    return new Promise(function (resolve, reject) {
      const request = indexedDB.open("mawaddi-library", 1);
      request.onupgradeneeded = function () {
        const db = request.result;
        if (!db.objectStoreNames.contains("courses")) {
          db.createObjectStore("courses", { keyPath: "id" });
        }
        if (!db.objectStoreNames.contains("files")) {
          const files = db.createObjectStore("files", { keyPath: "id" });
          files.createIndex("courseId", "courseId", { unique: false });
        }
      };
      request.onsuccess = function () {
        database = request.result;
        database.onversionchange = function () { database.close(); };
        resolve(database);
      };
      request.onerror = function () { reject(request.error || new Error("تعذر فتح مساحة التخزين.")); };
      request.onblocked = function () { reject(new Error("أغلق النسخ الأخرى من الموقع ثم أعد تحميل الصفحة.")); };
    });
  }

  function transact(storeNames, mode, action) {
    return new Promise(function (resolve, reject) {
      let transaction;
      try {
        transaction = database.transaction(storeNames, mode);
      } catch (error) {
        reject(error);
        return;
      }
      let result;
      transaction.oncomplete = function () {
        resolve(result && "result" in result ? result.result : result);
      };
      transaction.onabort = function () {
        reject(transaction.error || new Error("تعذر حفظ البيانات في المتصفح."));
      };
      transaction.onerror = function () {
        reject(transaction.error || new Error("حدث خطأ في مساحة التخزين."));
      };
      try {
        result = action(transaction);
      } catch (error) {
        transaction.abort();
        reject(error);
      }
    });
  }

  function makeId() {
    return typeof crypto !== "undefined" && crypto.randomUUID
      ? crypto.randomUUID()
      : Date.now().toString(36) + Math.random().toString(36).slice(2);
  }

  function showToast(message, isError) {
    elements.toast.textContent = message;
    elements.toast.classList.toggle("error", Boolean(isError));
    elements.toast.classList.add("visible");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { elements.toast.classList.remove("visible"); }, 3000);
  }

  function reportStorageError(error) {
    console.error("College materials storage error:", error);
    showToast("تعذر إكمال العملية. قد تكون مساحة المتصفح ممتلئة.", true);
  }

  function formatDate(timestamp) {
    return new Intl.DateTimeFormat("ar", { day: "numeric", month: "short", year: "numeric" })
      .format(new Date(timestamp));
  }

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + " بايت";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " كيلوبايت";
    return (bytes / (1024 * 1024)).toFixed(1) + " ميجابايت";
  }

  function makeButton(text, className, onClick) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = className;
    button.textContent = text;
    button.addEventListener("click", onClick);
    return button;
  }

  async function loadCourses() {
    courses = await transact("courses", "readonly", function (tx) {
      return tx.objectStore("courses").getAll();
    });
    courses.sort(function (a, b) { return b.updatedAt - a.updatedAt; });
    elements.courseCount.textContent = new Intl.NumberFormat("ar").format(courses.length);
    if (!courses.some(function (course) { return course.id === selectedCourseId; })) {
      selectedCourseId = courses.length ? courses[0].id : null;
    }
    renderCourseList();
    await renderSelectedCourse();
  }

  function renderCourseList() {
    elements.courseList.replaceChildren();
    const query = elements.search.value.trim().toLocaleLowerCase("ar");
    const visibleCourses = courses.filter(function (course) {
      return course.name.toLocaleLowerCase("ar").includes(query);
    });
    if (!visibleCourses.length) {
      const message = document.createElement("p");
      message.className = "files-empty";
      message.textContent = courses.length ? "لا توجد مادة بهذا الاسم." : "لم تضف أي مادة بعد.";
      elements.courseList.append(message);
      return;
    }
    visibleCourses.forEach(function (course) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "course-item" + (course.id === selectedCourseId ? " active" : "");
      button.setAttribute("aria-current", course.id === selectedCourseId ? "true" : "false");
      const name = document.createElement("strong");
      name.textContent = course.name;
      const date = document.createElement("small");
      date.textContent = "آخر تحديث " + formatDate(course.updatedAt);
      button.append(name, date);
      button.addEventListener("click", async function () {
        await saveNotes();
        selectedCourseId = course.id;
        renderCourseList();
        await renderSelectedCourse();
      });
      elements.courseList.append(button);
    });
  }

  async function saveNotes() {
    clearTimeout(notesTimer);
    const notes = document.querySelector(".notes-input");
    const course = courses.find(function (item) { return item.id === selectedCourseId; });
    if (!notes || !course) return;
    const value = notes.value;
    const status = document.querySelector(".save-status");
    if (status) status.textContent = "جارٍ الحفظ...";
    course.notes = value;
    course.updatedAt = Date.now();
    try {
      await transact("courses", "readwrite", function (tx) {
        return tx.objectStore("courses").put(course);
      });
      if (selectedCourseId === course.id) {
        const currentStatus = document.querySelector(".save-status");
        if (currentStatus) currentStatus.textContent = "تم الحفظ";
        renderCourseList();
      }
    } catch (error) {
      reportStorageError(error);
    }
  }

  async function renderSelectedCourse() {
    const course = courses.find(function (item) { return item.id === selectedCourseId; });
    elements.courseContent.replaceChildren();
    if (!course) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      const icon = document.createElement("span");
      icon.className = "empty-icon";
      icon.textContent = "📚";
      const title = document.createElement("h2");
      title.textContent = "ابدأ بتنظيم دراستك";
      const description = document.createElement("p");
      description.textContent = "أضف أول مادة لتكتب ملاحظاتك وتحفظ ملفاتها.";
      const addButton = makeButton("إضافة أول مادة", "primary-button", openAddDialog);
      empty.append(icon, title, description, addButton);
      elements.courseContent.append(empty);
      return;
    }

    const wrapper = document.createElement("div");
    const header = document.createElement("div");
    header.className = "course-header";
    const heading = document.createElement("div");
    const title = document.createElement("h2");
    title.textContent = course.name;
    const date = document.createElement("p");
    date.textContent = "أُضيفت في " + formatDate(course.createdAt);
    heading.append(title, date);
    const actions = document.createElement("div");
    actions.className = "course-actions";
    actions.append(
      makeButton("تعديل المادة", "small-button", function () { openEditDialog(course); }),
      makeButton("حذف المادة", "small-button delete", function () { deleteCourse(course); })
    );
    header.append(heading, actions);

    const notesHeading = document.createElement("div");
    notesHeading.className = "section-heading";
    const notesTitle = document.createElement("h3");
    notesTitle.textContent = "ملاحظات المادة";
    const saveStatus = document.createElement("span");
    saveStatus.className = "save-status";
    saveStatus.textContent = "يُحفظ تلقائيًا";
    notesHeading.append(notesTitle, saveStatus);
    const notes = document.createElement("textarea");
    notes.className = "notes-input";
    notes.setAttribute("aria-label", "ملاحظات " + course.name);
    notes.placeholder = "اكتب هنا ملخص المحاضرة، مواعيد الاختبارات، أو أي ملاحظات مهمة...";
    notes.value = course.notes || "";
    notes.addEventListener("input", function () {
      saveStatus.textContent = "تغييرات غير محفوظة";
      clearTimeout(notesTimer);
      notesTimer = setTimeout(function () { saveNotes(); }, 650);
    });
    notes.addEventListener("blur", saveNotes);

    const filesHeading = document.createElement("div");
    filesHeading.className = "section-heading files-heading";
    const filesTitle = document.createElement("h3");
    filesTitle.textContent = "ملفات المادة";
    const count = document.createElement("span");
    count.className = "file-count";
    count.textContent = "…";
    filesTitle.append(count);
    const uploadLabel = document.createElement("label");
    uploadLabel.className = "upload-button";
    uploadLabel.textContent = "＋ رفع ملفات";
    const uploadInput = document.createElement("input");
    uploadInput.type = "file";
    uploadInput.multiple = true;
    uploadInput.setAttribute("aria-label", "رفع ملفات للمادة");
    uploadInput.addEventListener("change", function () { addFiles(course, uploadInput); });
    uploadLabel.append(uploadInput);
    filesHeading.append(filesTitle, uploadLabel);
    const fileList = document.createElement("div");
    fileList.className = "file-list";
    wrapper.append(header, notesHeading, notes, filesHeading, fileList);
    elements.courseContent.append(wrapper);
    await renderFiles(course.id, fileList, count);
  }

  async function renderFiles(courseId, container, countElement) {
    try {
      const files = await transact("files", "readonly", function (tx) {
        return tx.objectStore("files").index("courseId").getAll(courseId);
      });
      files.sort(function (a, b) { return b.addedAt - a.addedAt; });
      countElement.textContent = new Intl.NumberFormat("ar").format(files.length);
      if (!files.length) {
        const empty = document.createElement("div");
        empty.className = "files-empty";
        empty.textContent = "لا توجد ملفات بعد. ارفع ملفات المحاضرات أو الملخصات هنا.";
        container.append(empty);
        return;
      }
      files.forEach(function (file) {
        const row = document.createElement("div");
        row.className = "file-item";
        const icon = document.createElement("span");
        icon.className = "file-icon";
        icon.setAttribute("aria-hidden", "true");
        icon.textContent = "▧";
        const info = document.createElement("div");
        info.className = "file-info";
        const name = document.createElement("strong");
        name.textContent = file.name;
        const details = document.createElement("small");
        details.textContent = formatSize(file.size) + " · رُفع " + formatDate(file.addedAt);
        info.append(name, details);
        const actions = document.createElement("div");
        actions.className = "file-actions";
        actions.append(
          makeButton("↓", "file-action", function () { downloadFile(file); }),
          makeButton("×", "file-action remove", function () { deleteFile(file); })
        );
        actions.lastElementChild.setAttribute("aria-label", "حذف الملف " + file.name);
        actions.firstElementChild.setAttribute("aria-label", "تنزيل الملف " + file.name);
        row.append(icon, info, actions);
        container.append(row);
      });
    } catch (error) {
      reportStorageError(error);
    }
  }

  function openAddDialog() {
    editingCourseId = null;
    elements.dialogTitle.textContent = "إضافة مادة";
    elements.saveCourse.textContent = "إضافة المادة";
    elements.courseName.value = "";
    elements.dialog.showModal();
    elements.courseName.focus();
  }

  function openEditDialog(course) {
    editingCourseId = course.id;
    elements.dialogTitle.textContent = "تعديل اسم المادة";
    elements.saveCourse.textContent = "حفظ التعديلات";
    elements.courseName.value = course.name;
    elements.dialog.showModal();
    elements.courseName.focus();
  }

  async function saveCourse(event) {
    event.preventDefault();
    const name = elements.courseName.value.trim();
    if (!name) return;
    await saveNotes();
    const now = Date.now();
    const existing = courses.find(function (course) { return course.id === editingCourseId; });
    const course = existing
      ? Object.assign({}, existing, { name: name, updatedAt: now })
      : { id: makeId(), name: name, notes: "", createdAt: now, updatedAt: now };
    try {
      await transact("courses", "readwrite", function (tx) {
        return tx.objectStore("courses").put(course);
      });
      selectedCourseId = course.id;
      elements.dialog.close();
      await loadCourses();
      showToast(existing ? "تم تعديل اسم المادة." : "تمت إضافة المادة.");
    } catch (error) {
      reportStorageError(error);
    }
  }

  async function deleteCourse(course) {
    if (!window.confirm("سيتم حذف مادة «" + course.name + "» وملاحظاتها وجميع ملفاتها. هل تريد المتابعة؟")) return;
    try {
      await saveNotes();
      await transact(["courses", "files"], "readwrite", function (tx) {
        const files = tx.objectStore("files");
        const request = files.index("courseId").openCursor(course.id);
        request.onsuccess = function () {
          const cursor = request.result;
          if (cursor) {
            cursor.delete();
            cursor.continue();
          } else {
            tx.objectStore("courses").delete(course.id);
          }
        };
        return undefined;
      });
      selectedCourseId = null;
      await loadCourses();
      showToast("تم حذف المادة وملفاتها.");
    } catch (error) {
      reportStorageError(error);
    }
  }

  async function addFiles(course, input) {
    const selectedFiles = Array.from(input.files || []);
    input.value = "";
    if (!selectedFiles.length) return;
    try {
      await saveNotes();
      await transact("files", "readwrite", function (tx) {
        const store = tx.objectStore("files");
        selectedFiles.forEach(function (file) {
          store.add({
            id: makeId(),
            courseId: course.id,
            name: file.name,
            type: file.type || "application/octet-stream",
            size: file.size,
            addedAt: Date.now(),
            blob: file
          });
        });
        return undefined;
      });
      await renderSelectedCourse();
      showToast(selectedFiles.length === 1 ? "تم رفع الملف." : "تم رفع الملفات.");
    } catch (error) {
      reportStorageError(error);
    }
  }

  function downloadFile(file) {
    const url = URL.createObjectURL(file.blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = file.name;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  async function deleteFile(file) {
    if (!window.confirm("هل تريد حذف الملف «" + file.name + "»؟")) return;
    try {
      await saveNotes();
      await transact("files", "readwrite", function (tx) {
        return tx.objectStore("files").delete(file.id);
      });
      await renderSelectedCourse();
      showToast("تم حذف الملف.");
    } catch (error) {
      reportStorageError(error);
    }
  }

  document.getElementById("add-course").addEventListener("click", openAddDialog);
  document.getElementById("add-course-secondary").addEventListener("click", openAddDialog);
  document.getElementById("add-course-empty").addEventListener("click", openAddDialog);
  document.getElementById("close-dialog").addEventListener("click", function () { elements.dialog.close(); });
  document.getElementById("cancel-dialog").addEventListener("click", function () { elements.dialog.close(); });
  elements.form.addEventListener("submit", saveCourse);
  elements.search.addEventListener("input", renderCourseList);
  applyTheme(readThemePreference(), false);
  elements.themeToggle.addEventListener("click", function () {
    applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark", true);
  });

  openDatabase()
    .then(loadCourses)
    .catch(function (error) {
      console.error("College materials app initialization failed:", error);
      elements.courseContent.replaceChildren();
      const message = document.createElement("div");
      message.className = "files-empty";
      message.textContent = "تعذر فتح التخزين المحلي في هذا المتصفح. جرّب متصفحًا حديثًا أو افتح الموقع عبر رابط HTTPS.";
      elements.courseContent.append(message);
      showToast("تعذر تشغيل مساحة التخزين المحلية.", true);
    });
}());
